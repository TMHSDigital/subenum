// Package passive names the keyless passive sources whose names seed a scan
// (#193): Certificate Transparency through crt.sh, and the Wayback Machine's
// URL index. A source only proposes candidates; the scan still resolves each
// one, so a stale name costs a query, never a false result.
package passive

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/TMHSDigital/subenum/internal/ct"
	"github.com/TMHSDigital/subenum/internal/wordlist"
)

// Source finds names under a domain without querying the domain's DNS.
type Source interface {
	// Name is the source's short name, as -sources takes it.
	Name() string
	// Names returns names under domain relative to it ("api", "dev.api"),
	// sorted and deduplicated.
	Names(ctx context.Context, domain string) ([]string, error)
}

// Truncated is returned with the names a source did get when it stopped at
// one of its limits before reading everything (#272): the names are good,
// but some hosts may be missing. Callers use the names and report it.
type Truncated struct {
	Source string // the source's -sources name
	Why    string // the limit it hit
}

func (t *Truncated) Error() string {
	return fmt.Sprintf("%s results truncated: %s; some hosts may be missing", Labels[t.Source], t.Why)
}

// Known lists the sources -sources accepts, in the order they run.
var Known = []string{"ct", "wayback"}

// Labels are human-readable names for messages.
var Labels = map[string]string{"ct": "Certificate Transparency", "wayback": "Wayback Machine"}

// Options configure the built-in sources.
type Options struct {
	// UserAgent identifies the client to each service.
	UserAgent string
	// BaseURLs replace a source's endpoint, by source name; tests point them
	// at local servers.
	BaseURLs map[string]string
}

// ParseList parses a comma-separated -sources value: known names only,
// lowercase, deduplicated, in Known order. Empty is no sources.
func ParseList(s string) ([]string, error) {
	want := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		name := strings.ToLower(strings.TrimSpace(part))
		if name == "" {
			continue
		}
		if !slices.Contains(Known, name) {
			return nil, fmt.Errorf("unknown source %q (want %s)", part, strings.Join(Known, ", "))
		}
		want[name] = true
	}
	var out []string
	for _, name := range Known {
		if want[name] {
			out = append(out, name)
		}
	}
	return out, nil
}

// New returns the built-in source called name.
func New(name string, opts Options) (Source, error) {
	switch name {
	case "ct":
		return ctSource{ct.Client{BaseURL: opts.BaseURLs["ct"], UserAgent: opts.UserAgent}}, nil
	case "wayback":
		return Wayback{BaseURL: opts.BaseURLs["wayback"], UserAgent: opts.UserAgent}, nil
	}
	return nil, fmt.Errorf("unknown source %q", name)
}

// Merge appends to entries the names that are not already in have, after
// them, so the entries' own order (and a resumed scan's positions) stays
// put, and records them in have. Names are relative to domain; wordlist.Build
// normalises them and drops invalid ones and ones too long for domain. It
// returns the entries and how many names were new. The CLI and pkg/subenum
// share it, so both merge sources the same way (#265).
func Merge(entries []string, have map[string]bool, names []string, domain string) ([]string, int) {
	extra, _, _ := wordlist.Build(names, domain)
	added := 0
	for _, e := range extra {
		if !have[e] {
			have[e] = true
			entries = append(entries, e)
			added++
		}
	}
	return entries, added
}

// ctSource reports a crt.sh answer cut off at its read limit as Truncated,
// with the names read before the cut (#251).
type ctSource struct{ ct.Client }

func (s ctSource) Names(ctx context.Context, domain string) ([]string, error) {
	names, err := s.Client.Names(ctx, domain)
	if errors.Is(err, ct.ErrTruncated) {
		_, why, _ := strings.Cut(err.Error(), ": ")
		return names, &Truncated{Source: "ct", Why: why}
	}
	return names, err
}
