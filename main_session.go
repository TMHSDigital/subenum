package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/scan"
	"github.com/TMHSDigital/subenum/internal/tui"
	"github.com/TMHSDigital/subenum/internal/wordlist"
)

// session is one CLI run: its flags and inputs, its writers, and what each
// target's scan produced. The phases of runWith are its methods, so per-run
// state is not threaded through helpers positionally (#158).
type session struct {
	a           runArgs
	args        []string     // the effective arguments (a -resume run's saved ones)
	resume      *resumeState // the state a -resume run continues; nil otherwise
	f           cliFlags
	fs          *flag.FlagSet
	positionals []string
	in          runtimeInputs
	format      output.Format
	settings    map[string]string // effective settings, saved for -resume
	targets     []string
	words       *wordlist.Prepared
	seeds       map[string]struct{} // -seeds names

	out       *output.Writer // stdout, and the -o file unless -diff
	fileOut   *output.Writer // the -o file under -diff; nil otherwise
	outFile   *output.File
	outWriter *bufio.Writer // the -o file's buffer; nil without -o
	diff      *differ

	targetResults []output.Result // the current target's results: -permute seeds, saved on interrupt
	takeovers     []output.Result // every target's takeover candidates, for -sarif
	restored      map[string]bool // names re-emitted from a -resume state
	refound       int             // restored names a resumed pass found again (#156)

	status        []string
	results       []targetResult
	runs          [][]output.Result // results per target, for -resume state
	entryDigests  []string          // per target, for -resume state
	failedTargets int
	anyDone       bool
	anyFailed     bool
	fileErr       bool // a file write error was reported
	started       time.Time
	signalCode    atomic.Int32 // 128+signum once a signal arrives
}

func runWith(a runArgs) (code int) {
	// completion, man (#88): handled before flag parsing.
	if code, ok := runSubcommand(a.args, a.stdout, a.stderr); ok {
		return code
	}
	s := &session{a: a, restored: map[string]bool{}}
	if code, done := s.parse(); done {
		return code
	}
	domain, code, ok := s.configure()
	if !ok {
		return code
	}
	if s.targets, ok = loadTargets(s.f, &s.in, domain, s.out); !ok {
		return exitFailure
	}
	if s.f.simZone != "" {
		stop, ok := startLabZone(&s.f, s.targets, s.out)
		if !ok {
			return exitFailure
		}
		defer stop()
	}
	if s.f.verbose {
		targetDesc := s.targets[0]
		if len(s.targets) > 1 {
			targetDesc = fmt.Sprintf("%d domains from %s", len(s.targets), s.f.domainList)
		}
		logVerboseStart(s.f, targetDesc, s.in.maxAttempts, s.out)
	}
	if !s.loadInputs() || !s.openOutputs() || !s.loadSeeds() {
		return exitFailure
	}
	s.setProgress()
	if s.outFile != nil {
		// Runs after the final return value is chosen. The results file
		// replaces an existing one only if a scan finished (#52); a failed
		// flush, close or rename means it is incomplete, so it must turn a
		// successful exit into a failure (#30). bufio errors are sticky, so a
		// failure already reported by Finish is not printed twice.
		defer func() {
			if err := s.outFile.Close(s.anyDone); err != nil {
				if !s.fileErr {
					s.out.Error("writing output file: %v", err)
				}
				if code == 0 {
					code = 1
				}
			}
		}()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopSignals := s.handleSignals(ctx, cancel)
	defer stopSignals()

	s.scanAll(ctx)
	return s.finish(ctx)
}

// parse reads the command line. done means the run ends here with code: a
// usage error, or -h, -tui, -print-config or -version.
func (s *session) parse() (code int, done bool) {
	a := s.a
	args, resume, resumeErr := resumeArgs(a.args)
	if resumeErr != nil {
		_, _ = fmt.Fprintf(a.stderr, "Error: %v\n", resumeErr)
		return exitUsage, true
	}
	defaults := newDefaultsLoader()
	f, positionals, fs, parseErr := parseFlagsWith(args, defaults.apply, a.stderr)
	s.args, s.resume, s.f, s.fs, s.positionals = args, resume, f, fs, positionals
	s.in = runtimeInputs{stdin: a.stdin, defaults: defaults}
	if errors.Is(parseErr, errConfig) {
		// -version, -print-config and -tui stay usable with a broken config,
		// so the bad value can be found and fixed (#116).
		if !f.showVersion && !f.printConfig && !f.tui {
			_, _ = fmt.Fprintf(a.stderr, "Error: %v\n", parseErr)
			return exitUsage, true
		}
		_, _ = fmt.Fprintf(a.stderr, "Warning: %v\n", parseErr)
		parseErr = nil
	}
	if parseErr != nil {
		// The FlagSet has already printed the error and usage.
		if errors.Is(parseErr, flag.ErrHelp) {
			return exitOK, true
		}
		return exitUsage, true
	}

	// -tui counts only as a real flag, not as the value of another flag
	// (-o -tui) or an argument after "--" (#58).
	if f.tui {
		return tui.Start(tuiOptions(f, fs, positionals, defaults, a.stderr)), true
	}

	if f.printConfig {
		defaults.printConfig(a.stdout, fs)
		return exitOK, true
	}

	// -version answers before anything else prints, banners included (#58).
	if f.showVersion {
		_, _ = fmt.Fprintln(a.stdout, formatVersion())
		return exitOK, true
	}
	return exitOK, false
}

// tuiOptions pre-fills the TUI form from the command line (#195): the domain
// argument and every flag the form has a field for, over SUBENUM_* and config
// file values. Flags the form has no field for are named in a warning, as are
// extra domain arguments and extra -w files (the form takes one wordlist).
func tuiOptions(f cliFlags, fs *flag.FlagSet, positionals []string, defaults *defaultsLoader, stderr io.Writer) tui.Options {
	settings := defaults.settings(fs)
	wired := map[string]bool{}
	for _, name := range tui.Flags() {
		wired[name] = true
	}
	var ignored []string
	fs.Visit(func(fl *flag.Flag) {
		switch {
		case fl.Name == "tui":
		case wired[fl.Name]:
			settings[fl.Name] = fl.Value.String()
		default:
			ignored = append(ignored, "-"+fl.Name)
		}
	})
	if len(f.wordlists.paths) > 1 {
		settings["w"] = f.wordlists.paths[0]
		_, _ = fmt.Fprintf(stderr, "Warning: the TUI takes one wordlist; using %s\n", f.wordlists.paths[0])
	}
	opts := tui.Options{Version: resolveVersion(), Settings: settings}
	if len(positionals) > 0 {
		opts.Domain = positionals[0]
	}
	if len(positionals) > 1 {
		ignored = append(ignored, positionals[1:]...)
	}
	if len(ignored) > 0 {
		_, _ = fmt.Fprintf(stderr, "Warning: -tui has no form field for %s; ignored\n", strings.Join(ignored, " "))
	}
	return opts
}

// wire points w at the run's injected streams.
func (s *session) wire(w *output.Writer) *output.Writer {
	w.SetStdout(s.a.stdout)
	w.SetStderr(s.a.stderr)
	return w
}

// configure resolves the flags into the run's inputs and checks them. On
// failure it has reported the error and returns the exit code.
func (s *session) configure() (domain string, code int, ok bool) {
	f, fs := &s.f, s.fs
	format, formatErr := output.ParseFormat(f.format)
	recordTypes, typesErr := dns.ParseTypes(f.recordTypes)
	maxAttempts, fromRetries, err := effectiveAttempts(f.attempts, f.retries, s.in.defaults.source(fs, "attempts"), s.in.defaults.source(fs, "retries"))
	s.format, s.in.recordTypes, s.in.maxAttempts = format, recordTypes, maxAttempts
	// Every writer of the run uses the injected streams.
	out := s.wire(output.New(nil, f.testMode, format))
	s.out = out
	out.SetQuiet(f.silent)
	if fromRetries {
		out.Info("Warning: -retries is deprecated, use -attempts instead") // quiet under -silent (#166)
	}
	if formatErr != nil {
		out.Error("%v", formatErr)
		return "", exitUsage, false
	}
	if typesErr != nil {
		out.Error("%v", typesErr)
		return "", exitUsage, false
	}
	if f.sarifFile != "" && !slices.Contains(recordTypes, "CNAME") {
		out.Info("Note: -sarif lists takeover candidates, which need CNAME lookups; add -type A,AAAA,CNAME")
	}
	if err != nil {
		out.Error("%v", err)
		return "", exitUsage, false
	}

	if !validateArgs(*f, s.positionals, fs, out) {
		return "", exitUsage, false
	}
	excludes, err := loadExcludes(*f, &s.in)
	if err != nil {
		out.Error("reading -exclude-file: %v", err)
		return "", exitFailure, false
	}
	s.in.excludes = excludes

	// Arguments are checked before any banner is printed or the resolver list
	// is read, so a usage error is the first thing a user sees (#120).
	domain, ok = validateFlags(*f, &s.in, s.positionals, fs, out)
	if !ok {
		return "", exitUsage, false
	}
	if f.testMode {
		s.announceSimulation()
	}

	pool, poolCode := loadPool(*f, &s.in, out)
	if poolCode != exitOK {
		return "", poolCode, false
	}
	s.in.pool = pool
	return domain, exitOK, true
}

// announceSimulation picks the simulation seed and prints the banner.
func (s *session) announceSimulation() {
	f, out := &s.f, s.out
	if f.seed == 0 {
		f.seed = rand.Uint64()
	}
	if f.silent {
		out.Notice("SIMULATION MODE: results are artificially generated (seed %d)", f.seed)
	}
	out.Info("")
	out.Info("╔════════════════════════════════════════════════════════════════════╗")
	out.Info("║  SIMULATION MODE ACTIVE - NO ACTUAL DNS QUERIES WILL BE PERFORMED  ║")
	out.Info("║  Results are artificially generated for educational purposes only  ║")
	out.Info("╚════════════════════════════════════════════════════════════════════╝")
	out.Info("Simulation seed: %d (pass -seed %d to reproduce these results)", f.seed, f.seed)
	out.Info("")
	if f.ct {
		// -ct is an HTTPS request to crt.sh: it would send the target
		// off the machine despite the banner above (#150).
		out.Info("Note: -ct is ignored in simulation mode, which sends nothing off the machine")
		f.ct = false
	}
}

// loadInputs checks a -resume run against its inputs and reads the wordlist
// and the -diff file. It runs before the output file is created, so a bad -w
// path does not truncate an existing -o target.
func (s *session) loadInputs() bool {
	f, out := s.f, s.out
	// The wordlist is read once (stdin can only be read once) and normalized
	// per target, since the name-length limit depends on the domain.
	if len(f.wordlists.paths) == 0 {
		out.Info("No -w given: using the %s. Pass -w for a larger or target-specific list.", bundledWordlistName)
	}
	s.settings = effectiveSettings(s.fs)
	if s.resume != nil {
		if err := s.resume.checkInputs(f); err != nil {
			out.Error("cannot resume: %v", err)
			return false
		}
		if err := s.resume.checkSettings(s.fs, s.in.defaults); err != nil {
			out.Error("cannot resume: %v", err)
			return false
		}
		out.Info("Resuming the interrupted run of: subenum %s", strings.Join(s.args, " "))
	}
	wordLines, err := readWordlist(f, &s.in)
	if err != nil {
		out.Error("reading wordlist file: %v", err)
		return false
	}
	// Normalized once for every target; per target only the name-length
	// limit differs (#182).
	s.words = wordlist.Prepare(wordLines)
	if probe, _, _ := s.words.For(""); len(probe) == 0 {
		out.Error("wordlist %s has no valid entries", f.wordlists.describe())
		return false
	}
	if s.resume != nil {
		// The bundled wordlist changes with the binary, so the file digests
		// alone cannot tell that a saved position still means the same entry.
		for _, target := range s.targets {
			if t := s.resume.target(target); t != nil && !t.Done && t.Entries != "" {
				if entries, _, _ := s.words.For(target); entryDigest(entries) != t.Entries {
					out.Error("cannot resume: the wordlist for %s changed since the interrupted run (a different -w file or subenum version); start a new scan instead", target)
					return false
				}
			}
		}
	}

	if f.diff != "" {
		previous, err := loadBaseline(f.diff)
		if err != nil {
			out.Error("reading -diff file: %v", err)
			return false
		}
		s.diff = &differ{previous: previous.names, current: map[string]struct{}{}}
		if f.diffRecords && !s.diff.withRecords(previous, s.in.recordTypes) {
			out.Info("Note: -diff-records: %s has no records (text format), so only names are compared; save results with -format jsonl, json or csv", f.diff)
		}
	}
	return true
}

// openOutputs creates the -o file and sets up the result writers.
func (s *session) openOutputs() bool {
	f := s.f
	combined, outFile, ok := openOutputFile(f.outputFile, f.testMode, s.format, s.out)
	if !ok {
		return false
	}
	s.wire(combined)
	s.outFile = outFile
	if outFile != nil {
		s.outWriter = outFile.Writer
	}
	// In -diff mode stdout carries only the changes while the -o file keeps
	// the full current results, ready to be the next run's -diff input (#84).
	if s.diff != nil && outFile != nil {
		s.fileOut = s.wire(output.NewFile(outFile.Writer, f.testMode, s.format))
	} else {
		s.out = combined
	}
	s.out.SetDiff(s.diff != nil)
	for _, w := range []*output.Writer{s.out, s.fileOut} {
		if w == nil {
			continue
		}
		// Bare names when piped or -silent (no "Found:" banner), human-friendly
		// on a terminal.
		w.SetPlain(f.silent || !isTerminal(s.a.stdout))
		w.SetQuiet(f.silent)
		w.SetShowRecords(f.showRecords)
		w.SetSeed(f.seed)
		w.SetTakeoverColumn(slices.Contains(s.in.recordTypes, "CNAME"))
	}
	return true
}

// loadSeeds reads the -seeds file, which implies -permute.
func (s *session) loadSeeds() bool {
	if s.f.seedsFile == "" {
		return true
	}
	s.f.permute = true
	seeds, err := loadPrevious(s.f.seedsFile)
	if err != nil {
		s.out.Error("reading -seeds file: %v", err)
		return false
	}
	s.seeds = seeds
	return true
}

// setProgress decides how progress is shown. A carriage-return progress line
// only makes sense on a terminal. When stderr is a pipe or file (2>&1, tee,
// CI logs) progress is off unless -progress was given explicitly, and then
// printed as whole lines (#78). SUBENUM_PROGRESS or a config value counts as
// explicit too (#116).
func (s *session) setProgress() {
	if s.f.silent {
		s.f.showProgress = false
	}
	if !isTerminal(s.a.stderr) {
		if s.in.defaults.source(s.fs, "progress") != sourceDefault {
			s.out.SetProgressLines(true)
		} else {
			s.f.showProgress = false
		}
	}
}

// handleSignals cancels the run on an interrupt or SIGTERM and records the
// exit code for it. The returned stop ends the signal handling.
func (s *session) handleSignals(ctx context.Context, cancel context.CancelFunc) (stop func()) {
	sigCh := make(chan os.Signal, 1)
	if testSignals != nil {
		sigCh = testSignals // tests deliver an interrupt on any OS
	}
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	if signalReady != nil {
		close(signalReady)
	}
	out := s.out
	go func() {
		select {
		case sig := <-sigCh:
			// Restore default handling so a second Ctrl+C force-quits a run
			// that is stuck draining (for example on a blocked stdout pipe).
			signal.Stop(sigCh)
			if sig == syscall.SIGTERM {
				out.Info("SIGTERM received, shutting down gracefully...")
				s.signalCode.Store(143)
			} else {
				out.Info("Interrupt received, shutting down gracefully (Ctrl+C again to force quit)...")
				s.signalCode.Store(130)
			}
			cancel()
		case <-ctx.Done():
		}
	}()
	return func() { signal.Stop(sigCh) }
}

// emitResult writes one found name: to stdout, or under -diff to the -o
// file and, when it changed, to stdout. Names restored from a -resume state
// were already written.
func (s *session) emitResult(ev scan.Event, permutation bool) {
	if s.restored[ev.Result.Subdomain] {
		s.refound++
		return
	}
	res := output.Result{Result: ev.Result, Permutation: permutation}
	s.targetResults = append(s.targetResults, res)
	if res.Takeover != "" {
		s.takeovers = append(s.takeovers, res)
	}
	if s.diff == nil {
		s.out.Emit(res)
		return
	}
	if s.fileOut != nil {
		s.fileOut.Emit(res)
	}
	if change, previous := s.diff.observe(res.Subdomain, res.Records); change != "" {
		res.Change, res.PreviousRecords = change, previous
		s.out.Emit(res)
	}
}

func (s *session) emitMain(ev scan.Event)        { s.emitResult(ev, false) }
func (s *session) emitPermutation(ev scan.Event) { s.emitResult(ev, true) }

// scanAll scans every target in turn. Each target is an independent scan:
// its own preflight, wildcard check, -max-queries budget, -rate limiter and
// reliability guard. Results share one writer, so -format json is a single
// array and CSV has a single header.
func (s *session) scanAll(ctx context.Context) {
	n := len(s.targets)
	s.status = make([]string, n)
	s.results = make([]targetResult, n)
	s.runs = make([][]output.Result, n)
	s.entryDigests = make([]string, n)
	s.started = time.Now()
	if s.f.maxDuration > 0 {
		// One budget for the whole run: under -dL, later targets get what
		// earlier ones left, and report what they skipped (#190).
		s.in.deadline = s.started.Add(s.f.maxDuration)
	}
	for i, target := range s.targets {
		if ctx.Err() != nil || !s.scanOneTarget(ctx, i, target) {
			break
		}
	}
	if n > 1 {
		s.out.Info("Targets:")
		for i, target := range s.targets {
			st := s.status[i]
			if st == "" {
				st = "not run"
			}
			s.out.Info("  %-8s %s", st, target)
		}
	}
}

// scanOneTarget runs target's main pass and its -permute pass, after
// restoring what an interrupted run saved for it. It reports whether to go
// on: after a reliability abort the resolver is overloaded, so the remaining
// targets are skipped rather than sent to it too (#82).
func (s *session) scanOneTarget(ctx context.Context, i int, target string) (next bool) {
	out := s.out
	if len(s.targets) > 1 {
		out.Info("=== [%d/%d] %s ===", i+1, len(s.targets), target)
	}
	entries, duplicates, skipped := s.words.For(target)
	if skipped > 0 {
		out.Info("Skipped %d invalid wordlist entries (not valid DNS labels, or name longer than 253 characters)", skipped)
	}
	if s.f.verbose {
		out.Info("Total wordlist entries: %d", len(entries))
		if duplicates > 0 {
			out.Info("Removed %d duplicate wordlist entries", duplicates)
		}
	}
	if len(entries) == 0 {
		out.Error("no valid wordlist entries for %s", target)
		s.anyFailed = true
		s.status[i] = "failed"
		s.results[i] = targetResult{failed: true, err: "no valid wordlist entries"}
		s.failedTargets++
		return true
	}
	s.targetResults = nil
	s.entryDigests[i] = entryDigest(entries)
	saved := s.resume.target(target)
	var ctInfo targetCT
	seeds := s.seeds
	if s.f.ct {
		ctInfo = certificateTransparency(ctx, target, saved, out)
		var added int
		entries, added = withCTEntries(entries, ctInfo.names, target)
		seeds = withCTSeeds(s.seeds, ctInfo.names, target)
		if ctInfo.fetched {
			out.Info("Certificate Transparency: %d names under %s, %d of them new candidates", len(ctInfo.names), target, added)
		}
	}
	pass := scanPass{domain: target, entries: entries, maxQueries: s.f.maxQueries}
	var mainSaved *resumePass
	restoredHits := 0 // permutation results restored from the state
	if saved != nil {
		mainSaved, restoredHits = s.restoreTarget(saved)
		if saved.Done {
			out.Info("%s was finished before the interrupt; %d results restored", target, len(saved.Results))
			s.results[i] = targetResult{done: true, final: mainSaved.event()}
			s.runs[i] = s.targetResults
			s.anyDone = true
			s.status[i] = "ok"
			return true
		}
		pass.resumeFrom, pass.resumeNames = saved.RootDone, mainPassNames(s.targetResults)
		out.Info("Resuming %s at wordlist entry %d of %d (%d results restored)", target, saved.RootDone, len(entries), len(saved.Results))
	}
	res := s.mainPass(ctx, pass, mainSaved)
	// -permute: a second pass over permutations of what was found (#72),
	// skipped after an interrupt or a resolver abort. Its seeds are the
	// main pass's names only, so a resumed pass rebuilds the same
	// candidate list, and it resumes from its own position (#107).
	if s.f.permute && res.done && !res.resolverAbort && s.signalCode.Load() == 0 {
		p := permuteInput{target: target, entries: entries, found: mainPassNames(s.targetResults), seeds: seeds, restoredHits: restoredHits}
		if saved != nil {
			p.prev = saved.Permute
		}
		s.refound = 0
		res.permutation = runPermutationPass(ctx, s, p)
		if p := res.permutation; p != nil && s.refound > 0 {
			p.found -= s.refound
			if p.pass.done {
				p.pass.final = withoutRefound(p.pass.final, s.refound)
			}
		}
		if p := res.permutation; p != nil && p.pass.failed {
			res.failed = true
		}
	}
	res.ct = ctInfo
	return s.recordTarget(i, res)
}

// restoreTarget re-emits what was found before the interrupt, so -o and the
// structured output hold the whole result set. It returns the main pass's
// saved state and the number of permutation results restored.
func (s *session) restoreTarget(saved *resumeTarget) (mainSaved *resumePass, restoredHits int) {
	for _, r := range saved.Results {
		s.emitResult(scan.Event{Result: r.Result}, r.Permutation)
		s.restored[r.Subdomain] = true
		if r.Permutation {
			restoredHits++
		}
	}
	mainSaved = &resumePass{RootDone: saved.RootDone, Stats: saved.Stats, Processed: saved.Processed, Total: saved.Total, Found: int64(len(saved.Results) - restoredHits)}
	return mainSaved, restoredHits
}

// mainPass scans a target's wordlist; saved is its state from an
// interrupted run, if any.
func (s *session) mainPass(ctx context.Context, p scanPass, saved *resumePass) targetResult {
	if saved != nil {
		left, ok := remainingBudget(s.f.maxQueries, saved.Processed)
		if !ok {
			s.out.Info("%s: the -max-queries budget of %d was spent before the interrupt", p.domain, s.f.maxQueries)
			return targetResult{done: true, final: saved.event()}
		}
		p.maxQueries = left
	}
	s.refound = 0
	res := scanTarget(ctx, s, p, s.emitMain)
	if saved != nil && res.done {
		res.final = saved.merge(withoutRefound(res.final, s.refound))
	}
	return res
}

// recordTarget stores how target i ended and reports whether to go on to
// the next target.
func (s *session) recordTarget(i int, res targetResult) (next bool) {
	s.results[i] = res
	s.runs[i] = s.targetResults
	s.anyDone = s.anyDone || res.done
	s.anyFailed = s.anyFailed || res.failed
	s.status[i] = "ok"
	switch {
	case res.failed:
		s.status[i] = "failed"
		s.failedTargets++
	case s.signalCode.Load() != 0:
		s.status[i] = "interrupted"
	}
	if res.resolverAbort && i < len(s.targets)-1 {
		s.out.Error("resolver %s looks overloaded; skipping the %d remaining targets (use -no-abort to continue)", s.f.dnsServer, len(s.targets)-1-i)
		for j := i + 1; j < len(s.targets); j++ {
			s.status[j] = "skipped"
			s.failedTargets++
		}
		return false
	}
	return true
}

// finish saves or removes the resume state, writes the run-quality report
// and the -stats and -sarif files, closes the structured output and returns
// the exit code. The deferred -o file close in runWith runs after it.
func (s *session) finish(ctx context.Context) int {
	f, out := s.f, s.out
	logPoolHealth(s.in.pool, out)

	if s.signalCode.Load() != 0 {
		saveResumeState(s)
	} else if s.resume != nil && !s.anyFailed {
		// The resumed run finished: its state file is spent (#109).
		if err := os.Remove(s.resume.path); err == nil {
			out.Info("Removed the finished run's resume state %s", s.resume.path)
		}
	}

	// The run-quality report (#70): the last jsonl line, and the -stats file.
	summary := buildSummary(s, time.Since(s.started))
	if s.diff != nil {
		summary.Diff = &output.DiffSummary{Previous: f.diff, Added: s.diff.added, Changed: s.diff.changed}
		sent := emitRemoved(ctx, s, &summary)
		summary.QueriesSent += sent
		if s.fileOut != nil {
			s.fileOut.Summary(summary)
		}
	}
	out.Summary(summary)
	if f.statsFile != "" {
		if err := output.WriteSummaryFile(f.statsFile, summary); err != nil {
			out.Error("writing -stats file: %v", err)
			s.fileErr = true
		}
	}
	if f.sarifFile != "" && s.anyDone {
		if err := output.WriteSARIF(f.sarifFile, resolveVersion(), s.takeovers); err != nil {
			out.Error("writing -sarif file: %v", err)
			s.fileErr = true
		}
	}
	// Finalize structured output only if a scan finished, so an early error
	// (such as wildcard detection without -force) does not emit an empty
	// JSON array or a bare CSV header. -format json streams its array (#181):
	// results already written, such as ones restored by -resume before the
	// target failed, are closed into a valid document even when no scan
	// finished.
	if s.anyDone || out.Started() || (s.fileOut != nil && s.fileOut.Started()) {
		if s.fileOut != nil {
			if err := s.fileOut.Finish(); err != nil {
				out.Error("writing output file: %v", err)
				s.fileErr = true
			}
		}
		if err := out.Finish(); err != nil {
			out.Error("writing output file: %v", err)
			s.fileErr = true
		}
		if f.testMode && !f.verbose {
			out.Info("NOTE: these results are SIMULATED; no DNS queries were sent (seed %d).", f.seed)
		}
	}
	ending := runEnding{
		signal: s.signalCode.Load(), fileErr: s.fileErr,
		targets: len(s.targets), failedTargets: s.failedTargets, anyFailed: s.anyFailed,
	}
	if s.diff != nil {
		ending.changes = s.diff.added + s.diff.removed + s.diff.changed
	}
	return ending.exitCode()
}
