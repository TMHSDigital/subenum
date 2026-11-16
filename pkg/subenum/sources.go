package subenum

import (
	"context"
	"fmt"

	"github.com/TMHSDigital/subenum/internal/candidates"
	"github.com/TMHSDigital/subenum/internal/passive"
)

// Source proposes names under a domain for Config.Sources (#193). The
// passive sources below do not query the domain's DNS; ZoneTransfer asks
// its name servers. Implement it to seed scans from your own inventory or
// another passive index.
type Source interface {
	// Names returns names under domain, relative to it ("api", "dev.api").
	// Names that are not valid in DNS are dropped by the scan.
	Names(ctx context.Context, domain string) ([]string, error)
}

var sourceUserAgent = passive.UserAgent("subenum-library")

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

// sourceLabel names sources[i] in Result.Sources (#273).
func sourceLabel(src Source, i int) string {
	if n, ok := src.(interface{ Name() string }); ok && n.Name() != "" {
		return n.Name()
	}
	return fmt.Sprintf("Sources[%d]", i)
}

// withSourceNames asks every source for domain's names at once (#271) and
// appends the ones entries lack, in the order of sources, in the candidate
// set the command line uses too, which knows who proposed each name (#273).
// A failed source is reported as a NoticeSource event.
func withSourceNames(ctx context.Context, out chan<- Event, sources []Source, domain string, entries []string) *candidates.Set {
	// The command line's fan-out (#355), over the caller's sources.
	answers := passive.Gather(len(sources), func(i int) ([]string, error) {
		if sources[i] == nil {
			return nil, nil
		}
		return sources[i].Names(ctx, domain)
	})
	cands := candidates.New(domain, entries, nil)
	for i, a := range answers {
		switch {
		case a.Truncated != "":
			// The names are good, only incomplete (#272).
			forward(ctx, out, Event{Kind: KindNotice, Notice: NoticeSource,
				Message: fmt.Sprintf("Sources[%d]: %s; scanning its %d names", i, a.Truncated, len(a.Names))})
		case !a.Fetched:
			forward(ctx, out, Event{Kind: KindNotice, Notice: NoticeSource,
				Message: fmt.Sprintf("Sources[%d]: %s; scanning without its names", i, a.Err)})
			continue
		}
		cands.Add(sourceLabel(sources[i], i), a.Names)
	}
	return cands
}
