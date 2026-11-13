package main

import "github.com/TMHSDigital/subenum/internal/output"

// resultLog keeps one target's results for the -permute seeds and, after an
// interrupt, the -resume state, which re-emits them so the -o file and the
// structured output hold the whole result set (#183).
//
// Re-emitting needs a result's records only when the output shows them, so
// unless full is set the log keeps just the names, plus whole copies of the
// few results that carry more than a name (a takeover hint, an internal
// address scope, a -permute hit). On a run with a million hits that is tens
// of megabytes instead of hundreds.
type resultLog struct {
	full bool // keep every result whole, records included

	all []output.Result // full: every result, in order

	// Compact: every name in order, the whole result for the indexes that
	// are more than a name, and the Simulated flag every result shares.
	names     []string
	extra     map[int]output.Result
	simulated bool
}

// add records one result.
func (l *resultLog) add(r output.Result) {
	if l.full {
		l.all = append(l.all, r)
		return
	}
	if len(l.names) == 0 {
		l.simulated = r.Simulated
	}
	if r.Takeover != "" || r.Internal != "" || r.Permutation || r.Simulated != l.simulated {
		if l.extra == nil {
			l.extra = map[int]output.Result{}
		}
		l.extra[len(l.names)] = r
	}
	l.names = append(l.names, r.Subdomain)
}

// results returns the logged results, in order. A compact log rebuilds them
// without records.
func (l *resultLog) results() []output.Result {
	if l.full {
		return l.all
	}
	if len(l.names) == 0 {
		return nil
	}
	out := make([]output.Result, len(l.names))
	for i, name := range l.names {
		if r, ok := l.extra[i]; ok {
			out[i] = r
			continue
		}
		out[i].Subdomain, out[i].Simulated = name, l.simulated
	}
	return out
}

// mainPassNames returns the names the main pass found, leaving out
// permutation hits: they are the -permute seeds.
func (l *resultLog) mainPassNames() []string {
	if l.full {
		return mainPassNames(l.all)
	}
	names := make([]string, 0, len(l.names))
	for i, name := range l.names {
		if r, ok := l.extra[i]; ok && r.Permutation {
			continue
		}
		names = append(names, name)
	}
	return names
}
