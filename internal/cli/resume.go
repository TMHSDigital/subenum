package cli

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

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/report"
	"github.com/TMHSDigital/subenum/internal/scan"
)

// An interrupted run (Ctrl+C, SIGTERM) writes a state file; `subenum
// -resume <file>` replays the original command line and continues where it
// stopped (#73). So does a run that -max-duration or the reliability guard
// stopped (#294).

const (
	resumeStateVersion = 1
	defaultStateFile   = "subenum-resume.json"
)

type resumeState struct {
	Version int               `json:"version"`
	Args    []string          `json:"args"`   // the original command line, without -resume
	Inputs  map[string]string `json:"inputs"` // input file -> sha256, checked before resuming
	// Settings are the effective flag values, including those from the
	// environment and config file. A resume does not re-apply them: it
	// compares them with its own (checkSettings) and refuses to run on a
	// difference (#109).
	Settings map[string]string `json:"settings,omitempty"`
	Targets  []resumeTarget    `json:"targets"`

	path string // the state file this run resumed from
}

type resumeTarget struct {
	Domain    string          `json:"domain"`
	Done      bool            `json:"done"`                // fully scanned before the interrupt
	RootDone  int             `json:"root_done"`           // wordlist entries settled, for the interrupted target
	MainDone  bool            `json:"main_done,omitempty"` // only the -permute pass was left; not scanned again (#358)
	Stats     scan.Stats      `json:"stats"`
	Processed int64           `json:"processed"`
	Total     int64           `json:"total"`
	Results   []output.Result `json:"results"`           // names found so far, re-emitted on resume
	Pending   []savedPending  `json:"pending,omitempty"` // left for -retry-inconclusive (#315)
	// Entries is the sha256 of the target's normalized wordlist, so a
	// changed bundled list (a new binary) or -w file refuses to resume (#109).
	Entries string `json:"entries,omitempty"`
	// Permute is the -permute pass's progress, once it had started (#107).
	Permute *resumePass `json:"permute,omitempty"`
	// CT holds the -ct names the interrupted run fetched, reused on resume
	// so the candidate list is the same (#130).
	CT        []string `json:"ct,omitempty"`
	CTFetched bool     `json:"ct_fetched,omitempty"`
	// Sources holds the names each passive source returned, by -sources
	// name, for every source whose lookup succeeded (#193). CT is also kept
	// in CT/CTFetched, as older runs wrote it.
	Sources map[string][]string `json:"sources,omitempty"`
	// AXFR holds the names an -axfr zone transfer gave, and AXFRServers the
	// name servers that allowed it, reused on resume like CT (#85).
	AXFR        []string `json:"axfr,omitempty"`
	AXFRServers []string `json:"axfr_servers,omitempty"`
	AXFRDone    bool     `json:"axfr_done,omitempty"`
	Denial      string   `json:"denial,omitempty"` // the zone's denial of existence, from -axfr (#234)
}

// resumePass is how far an interrupted scan pass got.
type resumePass struct {
	RootDone  int            `json:"root_done"`
	Stats     scan.Stats     `json:"stats"`
	Processed int64          `json:"processed"`
	Total     int64          `json:"total"`
	Found     int64          `json:"found"`
	Pending   []savedPending `json:"pending,omitempty"` // left for -retry-inconclusive (#315)
}

// savedPending is a name whose lookup was inconclusive and that the stopped
// run's -retry-inconclusive pass did not get to, with its outcome
// ("timeout", "refused" or "error"), so the resumed run retries it (#315).
type savedPending struct {
	Name    string `json:"name"`
	Outcome string `json:"outcome"`
}

// savePending converts the engine's Stats.Pending for the state file.
func savePending(pending []scan.Pending) []savedPending {
	var out []savedPending
	for _, p := range pending {
		out = append(out, savedPending{Name: p.Name, Outcome: p.Outcome.String()})
	}
	return out
}

// retryPrior converts saved names back for Config.RetryPrior.
func retryPrior(saved []savedPending) []scan.Pending {
	var out []scan.Pending
	for _, p := range saved {
		o := dns.OutcomeOther
		switch p.Outcome {
		case dns.OutcomeTimeout.String():
			o = dns.OutcomeTimeout
		case dns.OutcomeRefused.String():
			o = dns.OutcomeRefused
		}
		out = append(out, scan.Pending{Name: p.Name, Outcome: o})
	}
	return out
}

// handOverPending passes the names a saved pass left for its retry pass to
// the resumed pass, and takes them off the saved inconclusive list: the
// resumed pass lists the ones it still gets no answer for (#315).
func (p *resumePass) handOverPending(pass *scanPass, retry bool) {
	if !retry || len(p.Pending) == 0 {
		return
	}
	pass.retryPrior = retryPrior(p.Pending)
	handed := make(map[string]bool, len(p.Pending))
	for _, it := range p.Pending {
		handed[it.Name] = true
	}
	p.Stats.Inconclusive = slices.DeleteFunc(slices.Clone(p.Stats.Inconclusive), func(name string) bool { return handed[name] })
	p.Pending = nil
}

// newResumePass records a pass's final event, less what resuming it repeats.
// A pass that finished has nothing past its RootDone and, as a -permute pass
// is not recursive, nothing below depth 1 either.
func newResumePass(ev scan.Event) *resumePass {
	ev = withoutRepeat(ev)
	return &resumePass{RootDone: int(ev.Stats.RootDone), Stats: ev.Stats, Processed: ev.Processed, Total: ev.Total, Found: ev.Found,
		Pending: savePending(ev.Stats.Pending)}
}

// withoutRepeat drops from a stopped pass's final event the lookups and
// exclusions the resumed pass does again (scan.Repeat), so the two parts,
// merged, count each name once (#341). Found names stay: the resumed pass
// finds them again and withoutRefound takes them off its side, as before.
func withoutRepeat(ev scan.Event) scan.Event {
	r, s := ev.Stats.Repeat, &ev.Stats
	s.NXDomain = max(s.NXDomain-r.NXDomain, 0)
	s.Timeout = max(s.Timeout-r.Timeout, 0)
	s.Refused = max(s.Refused-r.Refused, 0)
	s.Other = max(s.Other-r.Other, 0)
	s.WildcardFiltered = max(s.WildcardFiltered-r.WildcardFiltered, 0)
	s.Excluded = max(s.Excluded-r.Excluded, 0)
	ev.Processed = max(ev.Processed-(r.Processed-r.Found), 0)
	if len(r.Inconclusive) > 0 {
		s.Inconclusive = slices.DeleteFunc(slices.Clone(s.Inconclusive), func(name string) bool {
			_, repeated := slices.BinarySearch(r.Inconclusive, name)
			return repeated
		})
	}
	s.Repeat = scan.Repeat{}
	return ev
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
	ev.Total = max(ev.Total-d, 0) // merge adds the saved part's processed, which has them (#341)
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

// pacingFlags may be given next to -resume to change how fast the rest of
// the scan goes, for example after timeouts piled up (#309). They change
// neither the candidate list nor the wildcard fingerprint, so the saved
// position keeps its meaning; the value says whether the flag is a boolean.
var pacingFlags = map[string]bool{
	"rate": false, "rate-per-resolver": false, "t": false, "timeout": false,
	"attempts": false, "auto-rate": true, "no-abort": true, "max-duration": false,
}

// pacingFlagList names the pacing flags for messages, in a fixed order.
func pacingFlagList() string {
	names := make([]string, 0, len(pacingFlags))
	for name := range pacingFlags {
		names = append(names, "-"+name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

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
// changed in between: the saved position would mean something else. The
// pacing flags may differ (#309).
func (st *resumeState) checkSettings(fs *flag.FlagSet, d *defaultsLoader) error {
	now := effectiveSettings(fs)
	names := make([]string, 0, len(st.Settings))
	for name := range st.Settings {
		if _, pacing := pacingFlags[name]; !pacing {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		if v, ok := now[name]; ok && v != st.Settings[name] {
			return fmt.Errorf("-%s is %q now but was %q in the stopped run (now set by %s); start a new scan instead of resuming", name, v, st.Settings[name], d.describe(fs, name))
		}
	}
	return nil
}

// resumeArgs looks for -resume in args. When present the only other flags
// allowed are the pacing flags; the state file's original arguments are
// returned in its place, with the pacing flags given applied over them (#309).
func resumeArgs(args []string) ([]string, *resumeState, error) {
	idx := -1
	path := ""
	var others []string // every argument but -resume and its state file
scan:
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			others = append(others, args[i:]...)
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
			continue
		}
		others = append(others, a)
	}
	if idx < 0 {
		return args, nil, nil
	}
	if path == "" {
		return nil, nil, fmt.Errorf("-resume needs a state file")
	}
	overrides, err := pacingOverrides(others)
	if err != nil {
		return nil, nil, err
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
	return withOverrides(st.Args, overrides), &st, nil
}

// pacingOverrides checks that the arguments given next to -resume are all
// pacing flags, and returns them with each value joined to its flag.
func pacingOverrides(args []string) ([]string, error) {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, _, hasValue := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-"), "=")
		isBool, ok := pacingFlags[name]
		if !ok || !strings.HasPrefix(a, "-") {
			return nil, fmt.Errorf("-resume takes only the pacing flags %s next to the state file, which holds the other arguments; got %q", pacingFlagList(), a)
		}
		if !isBool && !hasValue {
			if i+1 == len(args) {
				return nil, fmt.Errorf("flag needs an argument: -%s", name)
			}
			i++
			a = "-" + name + "=" + args[i]
		}
		out = append(out, a)
	}
	return out, nil
}

// withOverrides applies the pacing flags given next to -resume over the
// replayed arguments: placed after them, they win, and the next state file
// records them. They go before a "--", after which they would be positional.
func withOverrides(args, overrides []string) []string {
	if len(overrides) == 0 {
		return args
	}
	i := slices.Index(args, "--")
	if i < 0 {
		i = len(args)
	}
	return slices.Concat(args[:i:i], overrides, args[i:])
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

// inputDigests fingerprints the inputs a resume must find unchanged. That
// includes a -diff file that is also the -o file: a run that saves a resume
// state leaves it as it was (#297).
func inputDigests(f cliFlags) (map[string]string, error) {
	out := map[string]string{}
	paths := append(slices.Clone(f.wordlists.paths), f.domainList, f.excludeFile, f.resolvers, f.simZone, f.seedsFile, f.diff)
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
			return fmt.Errorf("%s changed since the stopped run; start a new scan instead of resuming", path)
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
	a.Excluded += b.Excluded
	a.PoolHits += b.PoolHits
	a.Confirmed += b.Confirmed
	a.Unconfirmed += b.Unconfirmed
	a.Takeover += b.Takeover
	a.Internal += b.Internal
	a.Partial += b.Partial
	a.Retried += b.Retried
	a.Recovered += b.Recovered
	a.Inconclusive = append(append([]string(nil), a.Inconclusive...), b.Inconclusive...)
	a.RateBackoffs += b.RateBackoffs
	if b.RateBackoffs > 0 || b.FinalRate > 0 {
		a.FinalRate = b.FinalRate // where the resumed run ended
	}
	// A part that ran out of -max-duration or was aborted left its remaining
	// candidates to the resumed part, so how that one ended is how the scan
	// ended, and the names the budget skipped are no longer skipped (#294).
	if a.Expired {
		a.Skipped = 0
	}
	a.Skipped += b.Skipped
	a.Aborted = b.Aborted
	a.Expired = b.Expired
	a.Wildcard = a.Wildcard || b.Wildcard
	if len(b.Fingerprint) > 0 {
		a.Fingerprint = b.Fingerprint
	}
	a.RootDone = b.RootDone
	a.Repeat = b.Repeat   // the saved part had its own taken off (withoutRepeat)
	a.Pending = b.Pending // the saved part handed its own over (handOverPending)
	return a
}

// savedSources is what the resume state keeps of a target's passive-source
// lookups: each source's names, and an empty list for one that failed. The
// resume position indexes the wordlist plus every source's names, so a
// resumed run must replay exactly the names the interrupted one scanned: a
// failed source fetched again could now succeed and shift every later
// candidate, skipping names silently (#237). That holds once the target's
// scan has started (scanned). Before it, no position depends on the lookup,
// and the failure may only be the interrupt cutting it short: the source is
// left out, so the resumed run asks it again (#299).
func savedSources(sources []targetSource, scanned bool) map[string][]string {
	saved := make(map[string][]string, len(sources))
	for _, src := range sources {
		switch {
		case src.Fetched:
			saved[src.Source] = src.Names
		case scanned:
			saved[src.Source] = []string{}
		}
	}
	if len(saved) == 0 {
		return nil
	}
	return saved
}

// saveResumeState writes the state file after an interrupt, or a run that
// -max-duration or the reliability guard stopped (#294), and tells the user
// how to continue. Runs that read stdin cannot be replayed. prev is the
// state this run resumed from, if any: a target interrupted again before its
// scan reported progress keeps the earlier resume point (#109), and one this
// run never reached keeps its saved state unchanged. It reports whether the
// state was saved.
func saveResumeState(s *session) bool {
	f, out, prev := s.f, s.out, s.resume
	if f.wordlists.readsStdin() || f.domainList == "-" {
		out.Info("Not saving resume state: the wordlist or domain list came from stdin")
		return false
	}
	inputs, err := inputDigests(f)
	if err != nil {
		out.Error("saving resume state: %v", err)
		return false
	}
	st := resumeState{Version: resumeStateVersion, Args: withSeed(s.args, f), Inputs: inputs, Settings: s.settings}
	for i, domain := range s.targets {
		saved := prev.target(domain)
		// A target finished before the interrupt was not scanned again, so
		// its saved state, sources and zone transfer included, stands (#315).
		if saved != nil && (s.status[i] == report.StatusNotRun || s.status[i] == report.StatusSkipped || saved.Done) {
			st.Targets = append(st.Targets, *saved)
			continue
		}
		res := s.results[i]
		ct := sourceByName(res.sources, "ct")
		// Whether the target's scan has started, in this run or the one it
		// resumed. Until then a failed source lookup or zone transfer may
		// only have been cut short by the interrupt, so it is not saved as
		// final and the resumed run tries it again (#299). A transfer the
		// earlier state had already settled stays settled.
		scanned := res.done || (saved != nil && saved.RootDone > 0)
		t := resumeTarget{Domain: domain, Results: s.runs[i].results(), Entries: s.entryDigests[i], CT: ct.Names, CTFetched: ct.Fetched,
			Sources: savedSources(res.sources, scanned)}
		if res.axfr.done && (scanned || (saved != nil && saved.AXFRDone)) {
			t.AXFR, t.AXFRServers, t.AXFRDone, t.Denial = res.axfr.names, res.axfr.allowed, true, string(res.axfr.denial)
		}
		// A target is finished only if its scan (and any -permute pass)
		// completed before the interrupt, with nothing left by -max-duration.
		t.Done = s.status[i] == report.StatusOK && res.done && !res.unfinished() &&
			(res.permutation == nil || res.permutation.candidates == 0 || (res.permutation.pass.done && !res.permutation.pass.unfinished()))
		// The -permute pass starts only once the main pass completed, so a
		// target with one left resumes in it, without the main pass (#358).
		t.MainDone = !t.Done && ((res.done && !res.unfinished() && res.permutation != nil) || (saved != nil && saved.MainDone))
		switch {
		case res.done:
			final := res.final
			if !t.Done && !t.MainDone {
				// The resumed run scans the main pass again from RootDone,
				// and re-expands every saved parent (#341).
				final = withoutRepeat(final)
			}
			t.Stats, t.Processed, t.Total = final.Stats, final.Processed, final.Total
			t.RootDone = int(final.Stats.RootDone)
			if !t.Done && !t.MainDone {
				t.Pending = savePending(final.Stats.Pending)
			}
		case saved != nil:
			// Interrupted during preflight or the wildcard probe, before the
			// resumed scan reported anything.
			t.Stats, t.Processed, t.Total, t.RootDone = saved.Stats, saved.Processed, saved.Total, saved.RootDone
			t.Pending = saved.Pending
		}
		if p := res.permutation; p != nil && p.pass.done {
			t.Permute = newResumePass(p.pass.final)
		} else if saved != nil {
			t.Permute = saved.Permute
		}
		st.Targets = append(st.Targets, t)
	}
	if err := writeResumeState(f.stateFile, st); err != nil {
		out.Error("saving resume state: %v", err)
		return false
	}
	out.Info("Saved resume state to %s; continue with: subenum -resume %s", f.stateFile, f.stateFile)
	return true
}

// writeResumeState saves where an interrupted run stopped.
func writeResumeState(path string, st resumeState) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return output.WriteFile(path, append(data, '\n'))
}
