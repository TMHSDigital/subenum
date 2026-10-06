package scan

import (
	"fmt"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/validate"
)

// Options are the user-facing scan settings. The CLI and the TUI each fill
// one in from their own inputs, then share Validate and Config, so the two
// front ends cannot drift apart in what they accept or how they scan (#80).
type Options struct {
	Domain      string
	Entries     []string
	Concurrency int
	TimeoutMs   int
	DNSServer   string
	Simulate    bool
	HitRate     int
	Seed        uint64
	Attempts    int
	Force       bool
	Types       []string
	Recursive   bool
	Depth       int
	Rate        int
	MaxQueries  int
	Exclude     []string
	Pool        *dns.Pool // -r resolver pool; DNSServer is then the trusted resolver
	// Resume point of an interrupted scan (#73); see Config.
	ResumeFrom    int
	ResumeParents []string
	NoAbort       bool
	Verbose       bool
	Logf          dns.Logf
}

// Validate checks the numeric ranges and the resolver address. Messages name
// each setting as a {token} that the front end renders (#100). The resolver is
// not checked in simulation mode, which sends no DNS traffic.
func (o Options) Validate() error {
	switch {
	case o.Concurrency < 1:
		return fmt.Errorf("concurrency ({concurrency}) must be at least 1, got %d", o.Concurrency)
	case o.TimeoutMs < 1:
		return fmt.Errorf("timeout ({timeout}) must be at least 1 ms, got %d", o.TimeoutMs)
	case o.Attempts < 1:
		return fmt.Errorf("attempts ({attempts}) must be at least 1, got %d", o.Attempts)
	case o.Simulate && (o.HitRate < 1 || o.HitRate > 100):
		return fmt.Errorf("hit rate ({hit_rate}) must be 1-100, got %d", o.HitRate)
	case o.Depth < 1:
		return fmt.Errorf("depth ({depth}) must be at least 1, got %d", o.Depth)
	case o.Rate < 0:
		return fmt.Errorf("rate ({rate}) must be 0 (unlimited) or a positive integer, got %d", o.Rate)
	case o.MaxQueries < 0:
		return fmt.Errorf("max queries ({max_queries}) must be 0 (unlimited) or a positive integer, got %d", o.MaxQueries)
	}
	if !o.Simulate {
		if err := validate.DNSServer(o.DNSServer); err != nil {
			return fmt.Errorf("DNS server %s: %w", o.DNSServer, err)
		}
	}
	return ValidateExcludes(o.Exclude)
}

// Config builds the scan.Config for these options.
func (o Options) Config() Config {
	return Config{
		Domain:      o.Domain,
		Entries:     o.Entries,
		Concurrency: o.Concurrency,
		Timeout:     time.Duration(o.TimeoutMs) * time.Millisecond,
		DNSServer:   o.DNSServer,
		Simulate:    o.Simulate,
		HitRate:     o.HitRate,
		Seed:        o.Seed,
		Attempts:    o.Attempts,
		Force:       o.Force,
		Verbose:     o.Verbose,
		Logf:        o.Logf,
		Rate:        o.Rate,
		Types:       o.Types,
		Recursive:   o.Recursive,
		Depth:       o.Depth,
		NoAbort:     o.NoAbort,
		MaxQueries:  o.MaxQueries,
		Exclude:     o.Exclude,
		Pool:        o.Pool,

		ResumeFrom:    o.ResumeFrom,
		ResumeParents: o.ResumeParents,
	}
}
