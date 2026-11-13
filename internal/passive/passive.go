// Package passive names the keyless passive sources whose names seed a scan
// (#193): Certificate Transparency through crt.sh, and the Wayback Machine's
// URL index. A source only proposes candidates; the scan still resolves each
// one, so a stale name costs a query, never a false result.
package passive

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/TMHSDigital/subenum/internal/ct"
)

// Source finds names under a domain without querying the domain's DNS.
type Source interface {
	// Name is the source's short name, as -sources takes it.
	Name() string
	// Names returns names under domain relative to it ("api", "dev.api"),
	// sorted and deduplicated.
	Names(ctx context.Context, domain string) ([]string, error)
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
		return ct.Client{BaseURL: opts.BaseURLs["ct"], UserAgent: opts.UserAgent}, nil
	case "wayback":
		return Wayback{BaseURL: opts.BaseURLs["wayback"], UserAgent: opts.UserAgent}, nil
	}
	return nil, fmt.Errorf("unknown source %q", name)
}
