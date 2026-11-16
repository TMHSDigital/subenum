package cli

import (
	"context"
	"errors"
	"sync"

	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/passive"
)

// targetSource is one passive source's lookup for a target (#130, #193).
type targetSource struct {
	source  string   // -sources name: ct, wayback
	names   []string // relative to the target
	fetched bool     // the lookup succeeded (names may still be empty)
	err     string
	// truncated says why a source that succeeded stopped at one of its
	// limits, so some hosts may be missing (#272).
	truncated string
}

// passiveNames asks every source for target's names at once (#271): the
// ones a resumed run saved, so its candidate list matches the interrupted
// run's, or a fresh lookup. The results, and the warning for each failed
// lookup (a warning, not a failed scan), keep the order of sources.
// baseURLs, set by tests, replace the sources' endpoints by name.
func passiveNames(ctx context.Context, sources []string, target string, saved *resumeTarget, out *output.Writer, baseURLs map[string]string) []targetSource {
	if len(sources) == 0 {
		return nil
	}
	opts := passive.Options{
		UserAgent: ProgramName + "/" + resolveVersion() + " (+https://github.com/TMHSDigital/subenum)",
		BaseURLs:  baseURLs,
	}
	res := make([]targetSource, len(sources))
	var wg sync.WaitGroup
	for i, name := range sources {
		res[i].source = name
		if names, ok := saved.sourceNames(name); ok {
			res[i].names, res[i].fetched = names, true
			continue
		}
		if saved != nil && saved.Done {
			// The target is not scanned again, so its candidates are not
			// needed: no lookup (#315).
			continue
		}
		src, err := passive.New(name, opts)
		if err != nil { // ParseList admitted only known names
			res[i].err = err.Error()
			continue
		}
		wg.Go(func() {
			names, err := src.Names(ctx, target)
			var tr *passive.Truncated
			switch {
			case errors.As(err, &tr):
				res[i].truncated = tr.Error()
			case err != nil:
				res[i].err = err.Error()
				return
			}
			res[i].names, res[i].fetched = names, true
		})
	}
	wg.Wait()
	for _, r := range res {
		switch {
		case !r.fetched && r.err != "":
			out.Info("Warning: %s; scanning %s without %s names", r.err, target, passive.Labels[r.source])
		case r.truncated != "":
			out.Info("Note: %s (%s, %d names)", r.truncated, target, len(r.names))
		}
	}
	return res
}

// sourceNames returns the names an interrupted run fetched from source, if
// it did. State files from before -sources keep CT names in CT/CTFetched.
func (t *resumeTarget) sourceNames(source string) ([]string, bool) {
	if t == nil {
		return nil, false
	}
	if names, ok := t.Sources[source]; ok {
		return names, true
	}
	if source == "ct" && t.CTFetched {
		return t.CT, true
	}
	return nil, false
}

// sourceByName returns the lookup of one source, if it ran.
func sourceByName(sources []targetSource, name string) targetSource {
	for _, s := range sources {
		if s.source == name {
			return s
		}
	}
	return targetSource{}
}
