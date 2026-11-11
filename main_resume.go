package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/scan"
)

// An interrupted run (Ctrl+C, SIGTERM) writes a state file; `subenum
// -resume <file>` replays the original command line and continues where it
// stopped (#73).

const (
	resumeStateVersion = 1
	defaultStateFile   = "subenum-resume.json"
)

type resumeState struct {
	Version int               `json:"version"`
	Args    []string          `json:"args"`   // the original command line, without -resume
	Inputs  map[string]string `json:"inputs"` // input file -> sha256, checked before resuming
	// Settings are the effective flag values, including those from the
	// environment and config file, which a resume re-applies (#109).
	Settings map[string]string `json:"settings,omitempty"`
	Targets  []resumeTarget    `json:"targets"`

	path string // the state file this run resumed from
}

type resumeTarget struct {
	Domain    string          `json:"domain"`
	Done      bool            `json:"done"`      // fully scanned before the interrupt
	RootDone  int             `json:"root_done"` // wordlist entries settled, for the interrupted target
	Stats     scan.Stats      `json:"stats"`
	Processed int64           `json:"processed"`
	Total     int64           `json:"total"`
	Results   []output.Result `json:"results"` // names found so far, re-emitted on resume
	// Entries is the sha256 of the target's normalized wordlist, so a
	// changed bundled list (a new binary) or -w file refuses to resume (#109).
	Entries string `json:"entries,omitempty"`
	// Permute is the -permute pass's progress, once it had started (#107).
	Permute *resumePass `json:"permute,omitempty"`
	// CT holds the -ct names the interrupted run fetched, reused on resume
	// so the candidate list is the same (#130).
	CT        []string `json:"ct,omitempty"`
	CTFetched bool     `json:"ct_fetched,omitempty"`
}

// resumePass is how far an interrupted scan pass got.
type resumePass struct {
	RootDone  int        `json:"root_done"`
	Stats     scan.Stats `json:"stats"`
	Processed int64      `json:"processed"`
	Total     int64      `json:"total"`
	Found     int64      `json:"found"`
}

// newResumePass records a pass's final event.
func newResumePass(ev scan.Event) *resumePass {
	return &resumePass{RootDone: int(ev.Stats.RootDone), Stats: ev.Stats, Processed: ev.Processed, Total: ev.Total, Found: ev.Found}
}

// event is the saved pass as a final event, for a pass with nothing left.
func (p *resumePass) event() scan.Event {
	return scan.Event{Kind: scan.EventDone, Stats: p.Stats, Processed: p.Processed, Total: p.Total, Found: p.Found}
}

// merge adds the saved part of a pass to the resumed part's final event.
func (p *resumePass) merge(ev scan.Event) scan.Event {
	ev.Stats = mergeStats(p.Stats, ev.Stats)
	ev.Processed += p.Processed
	ev.Found += p.Found
	ev.Total = max(ev.Total+p.Processed, p.Total)
	return ev
}

// withoutRefound drops from a resumed pass's final event the n names it found
// again after restoring them from the state. The resume point repeats up to a
// worker pool's worth of lookups, and the saved pass already counts those
// names as processed and found, so merging would count them twice (#156).
func withoutRefound(ev scan.Event, n int) scan.Event {
	d := int64(n)
	ev.Found = max(ev.Found-d, 0)
	ev.Processed = max(ev.Processed-d, 0)
	ev.Stats.Found = max(ev.Stats.Found-d, 0)
	return ev
}

// remainingBudget is the -max-queries budget left for a resumed pass that had
// already processed n names; ok is false once it is spent. Without the
// subtraction, every interrupt and resume could exceed the cap again (#108).
func remainingBudget(maxQueries int, processed int64) (left int, ok bool) {
	if maxQueries <= 0 {
		return 0, true
	}
	left = maxQueries - int(processed)
	return left, left > 0
}

// entryDigest fingerprints a target's normalized wordlist.
func entryDigest(entries []string) string {
	h := sha256.New()
	for _, e := range entries {
		_, _ = h.Write([]byte(e))
		_, _ = h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// unsavedSettings do not change what a scan queries, so a resume may differ
// in them: the seed is pinned in the replayed arguments, -max-duration is a
// budget for each invocation rather than for the scan (#190), and the rest
// only change what is printed.
var unsavedSettings = map[string]bool{"seed": true, "state": true, "v": true, "progress": true, "max-duration": true}

// effectiveSettings returns every setting's effective value.
func effectiveSettings(fs *flag.FlagSet) map[string]string {
	m := map[string]string{}
	fs.VisitAll(func(fl *flag.Flag) {
		if !noDefaultFlags[fl.Name] && !unsavedSettings[fl.Name] {
			m[fl.Name] = fl.Value.String()
		}
	})
	return m
}

// checkSettings refuses to resume when a setting differs from the
// interrupted run, for example because SUBENUM_DEPTH or the config file
// changed in between: the saved position would mean something else.
func (st *resumeState) checkSettings(fs *flag.FlagSet, d *defaultsLoader) error {
	now := effectiveSettings(fs)
	names := make([]string, 0, len(st.Settings))
	for name := range st.Settings {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if v, ok := now[name]; ok && v != st.Settings[name] {
			return fmt.Errorf("-%s is %q now but was %q in the interrupted run (now set by %s); start a new scan instead of resuming", name, v, st.Settings[name], d.describe(fs, name))
		}
	}
	return nil
}

// resumeArgs looks for -resume in args. When present it must be the only
// flag; the state file's original arguments are returned in its place.
func resumeArgs(args []string) ([]string, *resumeState, error) {
	idx := -1
	path := ""
scan:
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break scan // everything after is a positional argument (#166)
		}
		if a == "-resume" || a == "--resume" {
			rest := args[i+1:]
			if len(rest) == 0 {
				return nil, nil, fmt.Errorf("-resume needs a state file")
			}
			idx, path = i, rest[0]
			i++ // the state file is a value, not another flag
			continue
		}
		v, ok := strings.CutPrefix(a, "--resume=")
		if !ok {
			v, ok = strings.CutPrefix(a, "-resume=")
		}
		if ok {
			idx, path = i, v
		}
	}
	if idx < 0 {
		return args, nil, nil
	}
	if path == "" {
		return nil, nil, fmt.Errorf("-resume needs a state file")
	}
	if len(args) > 2 || (len(args) == 2 && path != args[1]) {
		return nil, nil, fmt.Errorf("-resume takes no other arguments; the state file holds the original ones")
	}
	data, err := os.ReadFile(path) //nolint:gosec // the user names their own state file
	if err != nil {
		return nil, nil, fmt.Errorf("reading -resume state: %w", err)
	}
	var st resumeState
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, nil, fmt.Errorf("-resume %s: %w", path, err)
	}
	if st.Version != resumeStateVersion {
		return nil, nil, fmt.Errorf("-resume %s: unsupported state version %d", path, st.Version)
	}
	st.path = path
	return st.Args, &st, nil
}

// fileDigest returns the sha256 of a file, or "" for none or stdin.
func fileDigest(path string) (string, error) {
	if path == "" || path == "-" {
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// inputDigests fingerprints the inputs a resume must find unchanged. The
// -diff file is left out when it is also the -o file, which an interrupted
// run rewrites with its partial results.
func inputDigests(f cliFlags) (map[string]string, error) {
	out := map[string]string{}
	diff := f.diff
	if diff == f.outputFile {
		diff = ""
	}
	paths := append(slices.Clone(f.wordlists.paths), f.domainList, f.excludeFile, f.resolvers, f.simZone, f.seedsFile, diff)
	for _, p := range paths {
		d, err := fileDigest(p)
		if err != nil {
			return nil, err
		}
		if d != "" {
			out[p] = d
		}
	}
	return out, nil
}

// checkInputs refuses to resume when an input file changed since the
// interrupted run: the saved position would point at different entries.
func (st *resumeState) checkInputs(f cliFlags) error {
	now, err := inputDigests(f)
	if err != nil {
		return err
	}
	for path, want := range st.Inputs {
		if now[path] != want {
			return fmt.Errorf("%s changed since the interrupted run; start a new scan instead of resuming", path)
		}
	}
	return nil
}

// target returns the saved state for domain, if any.
func (st *resumeState) target(domain string) *resumeTarget {
	if st == nil {
		return nil
	}
	for i := range st.Targets {
		if st.Targets[i].Domain == domain {
			return &st.Targets[i]
		}
	}
	return nil
}

// withSeed pins a simulation's seed in the replayed arguments, so the
// resumed part simulates the same answers.
func withSeed(args []string, f cliFlags) []string {
	if !f.testMode || slices.ContainsFunc(args, func(a string) bool { return a == "-seed" || a == "--seed" || len(a) > 6 && a[:6] == "-seed=" }) {
		return args
	}
	return append([]string{"-seed", strconv.FormatUint(f.seed, 10)}, args...)
}

// mergeStats adds a resumed run's counters to those saved before the
// interrupt, so the report covers the whole scan.
func mergeStats(a, b scan.Stats) scan.Stats {
	a.Found += b.Found
	a.NXDomain += b.NXDomain
	a.Timeout += b.Timeout
	a.Refused += b.Refused
	a.Other += b.Other
	a.WildcardFiltered += b.WildcardFiltered
	a.QueriesSent += b.QueriesSent
	a.Skipped += b.Skipped
	a.Excluded += b.Excluded
	a.PoolHits += b.PoolHits
	a.Confirmed += b.Confirmed
	a.Unconfirmed += b.Unconfirmed
	a.Takeover += b.Takeover
	a.Internal += b.Internal
	a.Retried += b.Retried
	a.Recovered += b.Recovered
	a.Inconclusive = append(append([]string(nil), a.Inconclusive...), b.Inconclusive...)
	a.RateBackoffs += b.RateBackoffs
	if b.RateBackoffs > 0 || b.FinalRate > 0 {
		a.FinalRate = b.FinalRate // where the resumed run ended
	}
	a.Aborted = a.Aborted || b.Aborted
	a.Expired = a.Expired || b.Expired
	a.Wildcard = a.Wildcard || b.Wildcard
	if len(b.Fingerprint) > 0 {
		a.Fingerprint = b.Fingerprint
	}
	a.RootDone = b.RootDone
	return a
}

// saveResumeState writes the state file after an interrupt and tells the
// user how to continue. Runs that read stdin cannot be replayed. prev is the
// state this run resumed from, if any: a target interrupted again before its
// scan reported progress keeps the earlier resume point (#109), and one this
// run never reached keeps its saved state unchanged.
func saveResumeState(s *session) {
	f, out, prev := s.f, s.out, s.resume
	if f.wordlists.readsStdin() || f.domainList == "-" {
		out.Info("Not saving resume state: the wordlist or domain list came from stdin")
		return
	}
	inputs, err := inputDigests(f)
	if err != nil {
		out.Error("saving resume state: %v", err)
		return
	}
	st := resumeState{Version: resumeStateVersion, Args: withSeed(s.args, f), Inputs: inputs, Settings: s.settings}
	for i, domain := range s.targets {
		saved := prev.target(domain)
		if s.status[i] == "" && saved != nil {
			st.Targets = append(st.Targets, *saved)
			continue
		}
		res := s.results[i]
		t := resumeTarget{Domain: domain, Results: s.runs[i], Entries: s.entryDigests[i], CT: res.ct.names, CTFetched: res.ct.fetched}
		switch {
		case res.done:
			t.Stats, t.Processed, t.Total = res.final.Stats, res.final.Processed, res.final.Total
			t.RootDone = int(res.final.Stats.RootDone)
		case saved != nil:
			// Interrupted during preflight or the wildcard probe, before the
			// resumed scan reported anything.
			t.Stats, t.Processed, t.Total, t.RootDone = saved.Stats, saved.Processed, saved.Total, saved.RootDone
		}
		if p := res.permutation; p != nil && p.pass.done {
			t.Permute = newResumePass(p.pass.final)
		} else if saved != nil {
			t.Permute = saved.Permute
		}
		// A target is finished only if its scan (and any -permute pass)
		// completed before the interrupt.
		t.Done = s.status[i] == "ok" && res.done && (res.permutation == nil || res.permutation.pass.done || res.permutation.candidates == 0)
		st.Targets = append(st.Targets, t)
	}
	if err := writeResumeState(f.stateFile, st); err != nil {
		out.Error("saving resume state: %v", err)
		return
	}
	out.Info("Saved resume state to %s; continue with: subenum -resume %s", f.stateFile, f.stateFile)
}

// writeResumeState saves where an interrupted run stopped.
func writeResumeState(path string, st resumeState) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	f, err := output.CreateFile(path)
	if err != nil {
		return err
	}
	_, werr := f.Write(append(data, '\n'))
	if cerr := f.Close(werr == nil); werr == nil {
		werr = cerr
	}
	return werr
}
