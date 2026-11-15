package scan

import (
	"context"
	"fmt"
	"iter"
	"reflect"
	"time"

	"github.com/TMHSDigital/subenum/internal/validate"
)

// Defaults every front end gives a setting that is not set (#262): the CLI's
// flag defaults, the TUI form's and pkg/subenum's Default constants, which
// tests keep equal to these.
const (
	DefaultConcurrency = 100
	DefaultTimeoutMs   = 1000
	DefaultHitRate     = 15
)

// Options are the user-facing scan settings. The CLI, the TUI and
// pkg/subenum each fill one in from their own inputs, then share Validate
// and Config, so the front ends cannot drift apart in what they accept or
// how they scan (#80). Each front end has a test that fails when a field
// here is left unset without a stated reason (#262).
//
// They are the engine's Config, documented there, plus the two settings
// that are only checked here (#331).
type Options struct {
	Config
	// MaxDuration is the run's time budget, only checked here: the front end
	// turns it into Deadline when the run starts, since one budget covers
	// every target of a run (#190).
	MaxDuration time.Duration
	// RatePerResolver is the pool's per-member rate cap, only checked here:
	// the front end applies it when it builds Pool (dns.NewPoolFromLines).
	RatePerResolver int
}

// Fields yields each setting of o by name: the embedded Config's exported
// fields, then Options' own. The front ends' drift tests walk it to check
// they set every setting (#262, #331).
func (o Options) Fields() iter.Seq2[string, reflect.Value] {
	return func(yield func(string, reflect.Value) bool) {
		var walk func(v reflect.Value) bool
		walk = func(v reflect.Value) bool {
			for i := range v.NumField() {
				f := v.Type().Field(i)
				switch {
				case f.Anonymous && f.Type.Kind() == reflect.Struct:
					if !walk(v.Field(i)) {
						return false
					}
				case f.IsExported():
					if !yield(f.Name, v.Field(i)) {
						return false
					}
				}
			}
			return true
		}
		walk(reflect.ValueOf(o))
	}
}

type noInconclusiveListKey struct{}

// WithoutInconclusiveList marks ctx for a pkg/subenum scan whose caller
// never reads Stats.Inconclusive (subenum mcp), so the library does not keep
// the list, as the CLI does not without -inconclusive (#300, #349). It is not
// part of the library's API.
func WithoutInconclusiveList(ctx context.Context) context.Context {
	return context.WithValue(ctx, noInconclusiveListKey{}, true)
}

// InconclusiveListOff reports whether ctx was marked by
// WithoutInconclusiveList.
func InconclusiveListOff(ctx context.Context) bool {
	off, _ := ctx.Value(noInconclusiveListKey{}).(bool)
	return off
}

// Validate checks the numeric ranges and the resolver address. Messages name
// each setting as a {token} that the front end renders (#100). The resolver is
// not checked in simulation mode, which sends no DNS traffic.
func (o Options) Validate() error {
	switch {
	case o.Concurrency < 1:
		return fmt.Errorf("concurrency ({concurrency}) must be at least 1, got %d", o.Concurrency)
	case o.Timeout < time.Millisecond:
		return fmt.Errorf("timeout ({timeout}) must be at least 1 ms, got %d", o.Timeout.Milliseconds())
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
	case o.MaxDuration < 0:
		return fmt.Errorf("max duration ({max_duration}) must be 0 (unlimited) or positive, got %s", o.MaxDuration)
	case o.RatePerResolver < 0:
		return fmt.Errorf("rate per resolver ({rate_per_resolver}) must be 0 (unlimited) or a positive integer, got %d", o.RatePerResolver)
	}
	if !o.Simulate {
		if err := validate.DNSServer(o.DNSServer); err != nil {
			return fmt.Errorf("DNS server %s: %w", o.DNSServer, err)
		}
	}
	return ValidateExcludes(o.Exclude)
}
