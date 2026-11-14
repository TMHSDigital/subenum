package subenum

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/TMHSDigital/subenum/internal/passive"
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
	return builtinSource("ct")
}

// WaybackMachine returns the source behind the CLI's -sources wayback:
// hostnames in the Wayback Machine's index of archived URLs. One HTTPS
// request per scan, no API key.
func WaybackMachine() Source {
	return builtinSource("wayback")
}

// builtinSource builds a source from the same registry as the CLI's
// -sources (#265).
func builtinSource(name string) Source {
	src, err := passive.New(name, passive.Options{UserAgent: sourceUserAgent})
	if err != nil { // name is one of passive.Known
		panic(err)
	}
	return src
}

// withSourceNames asks every source for domain's names at once (#271) and
// appends the ones entries lack, in the order of sources. A failed source is
// reported as a NoticeSource event.
func withSourceNames(ctx context.Context, out chan<- Event, sources []Source, domain string, entries []string) []string {
	type answer struct {
		names []string
		err   error
	}
	answers := make([]answer, len(sources))
	var wg sync.WaitGroup
	for i, src := range sources {
		if src == nil {
			continue
		}
		wg.Go(func() {
			names, err := src.Names(ctx, domain)
			answers[i] = answer{names, err}
		})
	}
	wg.Wait()
	have := make(map[string]bool, len(entries))
	for _, e := range entries {
		have[e] = true
	}
	for i, a := range answers {
		var tr *passive.Truncated
		switch {
		case errors.As(a.err, &tr):
			// The names are good, only incomplete (#272).
			forward(ctx, out, Event{Kind: KindNotice, Notice: NoticeSource,
				Message: fmt.Sprintf("Sources[%d]: %v; scanning its %d names", i, a.err, len(a.names))})
		case a.err != nil:
			forward(ctx, out, Event{Kind: KindNotice, Notice: NoticeSource,
				Message: fmt.Sprintf("Sources[%d]: %v; scanning without its names", i, a.err)})
			continue
		}
		entries, _ = passive.Merge(entries, have, a.names, domain)
	}
	return entries
}
