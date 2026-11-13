package subenum

import (
	"context"
	"fmt"

	"github.com/TMHSDigital/subenum/internal/ct"
	"github.com/TMHSDigital/subenum/internal/passive"
	"github.com/TMHSDigital/subenum/internal/wordlist"
)

// Source proposes names under a domain without querying the domain's DNS,
// for Config.Sources (#193). Implement it to seed scans from your own
// inventory or another passive index.
type Source interface {
	// Names returns names under domain, relative to it ("api", "dev.api").
	// Names that are not valid in DNS are dropped by the scan.
	Names(ctx context.Context, domain string) ([]string, error)
}

const sourceUserAgent = "subenum-library (+https://github.com/TMHSDigital/subenum)"

// CertificateTransparency returns the source behind the CLI's -ct: names in
// Certificate Transparency logs, through crt.sh. One HTTPS request per scan,
// no API key.
func CertificateTransparency() Source {
	return ct.Client{UserAgent: sourceUserAgent}
}

// WaybackMachine returns the source behind the CLI's -sources wayback:
// hostnames in the Wayback Machine's index of archived URLs. One HTTPS
// request per scan, no API key.
func WaybackMachine() Source {
	return passive.Wayback{UserAgent: sourceUserAgent}
}

// withSourceNames asks each source for domain's names and appends the ones
// entries lack. A failed source is reported as a NoticeSource event.
func withSourceNames(ctx context.Context, out chan<- Event, sources []Source, domain string, entries []string) []string {
	have := make(map[string]bool, len(entries))
	for _, e := range entries {
		have[e] = true
	}
	for i, src := range sources {
		if src == nil {
			continue
		}
		names, err := src.Names(ctx, domain)
		if err != nil {
			forward(ctx, out, Event{Kind: KindNotice, Notice: NoticeSource,
				Message: fmt.Sprintf("Sources[%d]: %v; scanning without its names", i, err)})
			continue
		}
		extra, _, _ := wordlist.Build(names, domain)
		for _, e := range extra {
			if !have[e] {
				have[e] = true
				entries = append(entries, e)
			}
		}
	}
	return entries
}
