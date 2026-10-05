package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"

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
	Targets []resumeTarget    `json:"targets"`
}

type resumeTarget struct {
	Domain    string          `json:"domain"`
	Done      bool            `json:"done"`      // fully scanned before the interrupt
	RootDone  int             `json:"root_done"` // wordlist entries settled, for the interrupted target
	Stats     scan.Stats      `json:"stats"`
	Processed int64           `json:"processed"`
	Total     int64           `json:"total"`
	Results   []output.Result `json:"results"` // names found so far, re-emitted on resume
}

// resumeArgs looks for -resume in args. When present it must be the only
// flag; the state file's original arguments are returned in its place.
func resumeArgs(args []string) ([]string, *resumeState, error) {
	idx := -1
	path := ""
	for i, a := range args {
		switch {
		case a == "-resume" || a == "--resume":
			if i+1 < len(args) {
				idx, path = i, args[i+1]
			} else {
				return nil, nil, fmt.Errorf("-resume needs a state file")
			}
		case len(a) > 8 && (a[:8] == "-resume=" || (len(a) > 9 && a[:9] == "--resume=")):
			idx, path = i, a[len("-resume="):]
			if a[1] == '-' {
				path = a[len("--resume="):]
			}
		}
	}
	if idx < 0 {
		return args, nil, nil
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

// inputDigests fingerprints the inputs a resume must find unchanged.
func inputDigests(f cliFlags) (map[string]string, error) {
	out := map[string]string{}
	for _, p := range []string{f.wordlistFile, f.domainList, f.excludeFile, f.resolvers} {
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
	a.Aborted = a.Aborted || b.Aborted
	a.Wildcard = a.Wildcard || b.Wildcard
	if len(b.Fingerprint) > 0 {
		a.Fingerprint = b.Fingerprint
	}
	a.RootDone = b.RootDone
	return a
}

// saveResumeState writes the state file after an interrupt and tells the
// user how to continue. Runs that read stdin cannot be replayed.
func saveResumeState(f cliFlags, args []string, targets, status []string, results []targetResult, runs [][]output.Result, out *output.Writer) {
	if f.wordlistFile == "-" || f.domainList == "-" {
		out.Info("Not saving resume state: the wordlist or domain list came from stdin")
		return
	}
	inputs, err := inputDigests(f)
	if err != nil {
		out.Error("saving resume state: %v", err)
		return
	}
	st := resumeState{Version: resumeStateVersion, Args: withSeed(args, f), Inputs: inputs}
	for i, domain := range targets {
		t := resumeTarget{Domain: domain, Results: runs[i]}
		res := results[i]
		if res.done {
			t.Stats, t.Processed, t.Total = res.final.Stats, res.final.Processed, res.final.Total
			t.RootDone = int(res.final.Stats.RootDone)
		}
		// A target is finished only if its scan (and any -permute pass)
		// completed before the interrupt.
		t.Done = status[i] == "ok" && res.done && (res.permutation == nil || res.permutation.pass.done || res.permutation.candidates == 0)
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
