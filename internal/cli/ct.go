package cli

import (
	"context"

	"github.com/TMHSDigital/subenum/internal/passive"
)

// targetSource is one passive source's lookup for a target (#130, #193).
type targetSource = passive.Lookup

// passiveNames asks every source for target's names at once (#271): the
// ones a resumed run saved, so its candidate list matches the interrupted
// run's, or a fresh lookup. The results, and the warning for each failed
// lookup (a warning, not a failed scan), keep the order of sources.
// Those lines go to info. baseURLs, set by tests, replace the sources'
// endpoints by name.
func passiveNames(ctx context.Context, sources []string, target string, saved *resumeTarget, info func(string, ...any), baseURLs map[string]string) []targetSource {
	if len(sources) == 0 {
		return nil
	}
	opts := passive.Options{
		UserAgent: passive.UserAgent(ProgramName + "/" + resolveVersion()),
		BaseURLs:  baseURLs,
	}
	res := make([]targetSource, len(sources))
	var fetch []string // the sources to ask (ParseList admitted only known names)
	var at []int       // their places in res
	for i, name := range sources {
		res[i].Source = name
		if names, ok := saved.sourceNames(name); ok {
			res[i].Names, res[i].Fetched = names, true
			continue
		}
		if saved != nil && saved.Done {
			// The target is not scanned again, so its candidates are not
			// needed: no lookup (#315).
			continue
		}
		fetch, at = append(fetch, name), append(at, i)
	}
	for j, l := range passive.FetchAll(ctx, fetch, opts, target) {
		res[at[j]] = l
	}
	for _, r := range res {
		switch {
		case !r.Fetched && r.Err != "":
			info("Warning: %s; scanning %s without %s names", r.Err, target, passive.Labels[r.Source])
		case r.Truncated != "":
			info("Note: %s (%s, %d names)", r.Truncated, target, len(r.Names))
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
		if s.Source == name {
			return s
		}
	}
	return targetSource{}
}
