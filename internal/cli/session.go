package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/TMHSDigital/subenum/internal/candidates"
	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/passive"
	"github.com/TMHSDigital/subenum/internal/report"
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
	logFormat   output.LogFormat  // -log-format (#198)
	logErr      error             // an invalid -log-format, reported by configure
	settings    map[string]string // effective settings, saved for -resume
	targets     []string
	words       *wordlist.Prepared
	deepWords   *wordlist.Prepared  // -recursive-w; nil means words (#403)
	seeds       map[string]struct{} // -seeds names

	out     *output.Writer // stdout: every result, or under -diff the changes
	outputs []outputTarget // the -o files and their formats (#334)
	files   []resultFile   // the open -o files, each with the full current results
	diff    *differ

	target        string          // the target being scanned, named in each result (#422)
	targetResults resultLog       // the current target's results: -permute seeds, saved on interrupt
	takeovers     []output.Result // every target's takeover candidates, for -sarif
	cands         *candidates.Set // the current target's candidates: what proposed each name (#273)
	foundBy       map[string]int  // the current target's results per source (#273)
	restored      map[string]bool // names re-emitted from a -resume state
	refound       refoundCount    // restored names a resumed pass found again (#156, #408)

	status        []report.Status
	results       []targetResult
	runs          []resultLog // results per target, for -resume state
	entryDigests  []string    // per target, for -resume state
	failedTargets int
	anyDone       bool
	anyFailed     bool
	fileErr       bool // a file write error was reported
	keepBaseline  bool // an -o file is also the -diff file and a resume needs it unchanged
	started       time.Time
	signalCode    atomic.Int32 // 128+signum once a signal arrives
}

func runWith(a runArgs) (code int) {
	// completion, man (#88) and mcp (#131): handled before flag parsing.
	if len(a.args) > 0 && a.args[0] == "mcp" {
		return runMCP(a.args[1:], a.stdin, a.stdout, a.stderr)
	}
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
	// Seeds are read before the -o file is opened: a failure after opening
	// would return before its deferred Close is registered and leave the
	// temporary file behind (#212).
	if !s.loadInputs() || !s.loadSeeds() {
		return exitFailure
	}
	// Before the -o file is opened: a dry run writes no results (#192).
	if s.f.dryRun {
		return s.dryRun()
	}
	if !s.openOutputs() {
		return exitFailure
	}
	s.setProgress()
	if len(s.files) > 0 {
		// Runs after the final return value is chosen. A results file
		// replaces an existing one only if a scan finished (#52); a failed
		// flush, close or rename means it is incomplete, so it must turn a
		// successful exit into a failure (#30). bufio errors are sticky, so a
		// failure already reported by Finish is not printed twice.
		defer func() {
			for _, rf := range s.files {
				keep := s.keepBaseline && samePath(rf.path, s.f.diff)
				if err := rf.file.Close(s.anyDone && !keep); err != nil {
					if !rf.reported {
						s.out.Error("writing output file: %v", err)
					}
					if code == 0 {
						code = 1
					}
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
	// The FlagSet's own messages are held back until -log-format is known:
	// under json a parse error becomes one JSON line instead (#198).
	var flagOut bytes.Buffer
	f, positionals, fs, parseErr := parseFlagsWith(args, defaults.apply, &flagOut)
	fs.SetOutput(a.stderr)
	s.args, s.resume, s.f, s.fs, s.positionals = args, resume, f, fs, positionals
	s.in = runtimeInputs{stdin: a.stdin, defaults: defaults}
	s.logFormat, s.logErr = output.ParseLogFormat(f.logFormat)
	diag := s.wire(output.New(nil, false, output.FormatText))
	logJSON := diag.LogJSON()
	if !logJSON || errors.Is(parseErr, flag.ErrHelp) {
		_, _ = flagOut.WriteTo(a.stderr) // -h output is help text, not a diagnostic
	}
	if errors.Is(parseErr, errConfig) {
		// -version, -print-config and -tui stay usable with a broken config,
		// so the bad value can be found and fixed (#116).
		if !f.showVersion && !f.printConfig && !f.tui {
			diag.Error("%v", parseErr)
			return exitUsage, true
		}
		diag.Notice("Warning: %v", parseErr)
		parseErr = nil
	}
	if parseErr != nil {
		// The FlagSet has already printed the error and usage, unless the
		// diagnostics are JSON.
		if errors.Is(parseErr, flag.ErrHelp) {
			return exitOK, true
		}
		if logJSON {
			diag.Error("%v", parseErr)
		}
		return exitUsage, true
	}

	// -tui counts only as a real flag, not as the value of another flag
	// (-o -tui) or an argument after "--" (#58).
	if f.tui {
		// The form cannot represent lab zones; never discard a lab request.
		if f.simZone != "" {
			diag.Error("-tui cannot be combined with %s; run the lab without -tui", defaults.describe(fs, "simulate-zone"))
			return exitUsage, true
		}
		return tui.Start(tuiOptions(f, fs, positionals, defaults, diag)), true
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
func tuiOptions(f cliFlags, fs *flag.FlagSet, positionals []string, defaults *defaultsLoader, diag *output.Writer) tui.Options {
	settings := defaults.settings(fs)
	wired := map[string]bool{}
	for _, name := range tui.Flags() {
		wired[name] = true
	}
	var ignored []string
	fs.Visit(func(fl *flag.Flag) {
		switch {
		case fl.Name == "tui", fl.Name == "ct": // -ct goes to Sources, below
		case wired[fl.Name]:
			settings[fl.Name] = fl.Value.String()
		default:
			ignored = append(ignored, "-"+fl.Name)
		}
	})
	if f.ct {
		// The form has no -ct field: -ct is the ct source of -sources, which
		// the Sources field takes (#348).
		sources := strings.Split(settings["sources"], ",")
		if !slices.Contains(sources, "ct") {
			settings["sources"] = strings.Trim(settings["sources"]+",ct", ",")
		}
	}
	if len(f.wordlists.paths) > 1 {
		settings["w"] = f.wordlists.paths[0]
		diag.Notice("Warning: the TUI takes one wordlist; using %s", f.wordlists.paths[0])
	}
	if len(f.outputs.specs) > 0 {
		// The form has one output file and one format (#334).
		format, path := splitOutputSpec(f.outputs.specs[0])
		settings["o"] = path
		if format != "" {
			settings["format"] = format
		}
		if len(f.outputs.specs) > 1 {
			diag.Notice("Warning: the TUI takes one output file; using %s", path)
		}
	}
	opts := tui.Options{Version: resolveVersion(), Settings: settings}
	if len(positionals) > 0 {
		opts.Domain = positionals[0]
	}
	if len(positionals) > 1 {
		ignored = append(ignored, positionals[1:]...)
	}
	if len(ignored) > 0 {
		diag.Notice("Warning: -tui has no form field for %s; ignored", strings.Join(ignored, " "))
	}
	return opts
}

// wire points w at the run's injected streams.
func (s *session) wire(w *output.Writer) *output.Writer {
	w.SetStdout(s.a.stdout)
	w.SetStderr(s.a.stderr)
	w.SetLogFormat(s.logFormat)
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
	outputs, outputsErr := parseOutputs(f.outputs.specs, format)
	if outputsErr == nil {
		outputsErr = checkOutputFiles(*f, outputs)
	}
	if outputsErr != nil {
		out.Error("%v", outputsErr)
		return "", exitUsage, false
	}
	s.outputs = outputs
	if s.logErr != nil {
		out.Error("%v", s.logErr)
		return "", exitUsage, false
	}
	if typesErr != nil {
		out.Error("%v", typesErr)
		return "", exitUsage, false
	}
	if f.sarifFile != "" && !dns.HintsTakeover(recordTypes) {
		out.Info("Note: -sarif lists takeover candidates, which need CNAME (or NS) lookups; add -type A,AAAA,CNAME")
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
	providers, err := loadTakeoverProviders(*f, &s.in)
	if err != nil {
		out.Error("%v", err)
		return "", exitUsage, false
	}
	s.in.providers = providers
	if f.providersFile != "" && !slices.Contains(recordTypes, "CNAME") {
		out.Info("Note: -takeover-providers matches CNAME targets; add -type A,AAAA,CNAME")
	}
	sources, err := passive.ParseList(f.sources)
	if err != nil {
		out.Error("-sources: %v", err)
		return "", exitUsage, false
	}
	if f.ct && !slices.Contains(sources, "ct") {
		sources = append([]string{"ct"}, sources...) // -ct is -sources ct; ct runs first
	}
	s.in.sources = sources

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
	if f.silent || out.LogJSON() {
		// JSON diagnostics get this one event in place of the banner (#198).
		out.NoticeOf("simulation", "SIMULATION MODE: results are artificially generated (seed %d)", f.seed)
	}
	if !out.LogJSON() {
		out.Info("")
		out.Info("╔════════════════════════════════════════════════════════════════════╗")
		out.Info("║  SIMULATION MODE ACTIVE - NO ACTUAL DNS QUERIES WILL BE PERFORMED  ║")
		out.Info("║  Results are artificially generated for educational purposes only  ║")
		out.Info("╚════════════════════════════════════════════════════════════════════╝")
		out.Info("Simulation seed: %d (pass -seed %d to reproduce these results)", f.seed, f.seed)
		out.Info("")
	}
	if len(s.in.sources) > 0 {
		// Passive sources are HTTPS requests (crt.sh, the Wayback Machine):
		// they would send the target off the machine despite the banner
		// above (#150, #193).
		which := "-sources is"
		switch {
		case f.ct && f.sources == "":
			which = "-ct is"
		case f.ct:
			which = "-ct and -sources are"
		}
		out.Info("Note: %s ignored in simulation mode, which sends nothing off the machine", which)
		f.ct, s.in.sources = false, nil
	}
	if f.axfr {
		out.Info("Note: -axfr is ignored in simulation mode, which sends no DNS queries")
		f.axfr = false
	}
}

// loadInputs checks a -resume run against its inputs and reads the wordlist
// and the -diff file. It runs before the output file is created, so a bad -w
// path does not truncate an existing -o target.
func (s *session) loadInputs() bool {
	f, out := s.f, s.out
	// The wordlist is read once (stdin can only be read once) and normalized
	// per target, since the name-length limit depends on the domain.
	if len(f.wordlists.paths) == 0 && f.hostsFile == "" {
		out.Info("No -w given: using the %s. Pass -w for a larger or target-specific list.", defaultWordlistName(f))
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
		out.Info("Resuming the stopped run of: subenum %s", strings.Join(s.args, " "))
	}
	// Normalized once, while it is read, for every target; per target only
	// the name-length limit differs (#182, #248).
	words, err := prepareWordlist(f, &s.in)
	if err != nil {
		out.Error("reading wordlist file: %v", err)
		return false
	}
	s.words = words
	if s.deepWords, err = prepareDeepWordlist(f, &s.in); err != nil {
		out.Error("reading -recursive-w file: %v", err)
		return false
	}
	if s.deepWords != nil {
		if probe, _, _ := s.deepWords.For(""); len(probe) == 0 {
			out.Error("-recursive-w %s has no valid entries", f.deepWords.describe())
			return false
		}
	}
	if probe, _, _ := s.words.For(""); len(probe) == 0 {
		if f.hostsFile != "" {
			out.Error("-hosts %s has no valid host names", f.hostsFile)
		} else {
			out.Error("wordlist %s has no valid entries", f.wordlists.describe())
		}
		return false
	}
	if f.hostsFile != "" {
		// Each target looks up only the names under it; the rest are out of
		// scope and never queried (#351).
		s.words.LimitTo(s.targets)
		if n := s.words.Outside(); n > 0 {
			out.Info("Note: %d -hosts names are under none of the targets; skipped them", n)
		}
	}
	if s.resume != nil {
		// The bundled wordlist changes with the binary, so the file digests
		// alone cannot tell that a saved position still means the same entry.
		for _, target := range s.targets {
			if t := s.resume.target(target); t != nil && !t.Done && t.Entries != "" {
				if entries, _, _ := s.words.For(target); entryDigest(entries) != t.Entries {
					out.Error("cannot resume: the wordlist for %s changed since the stopped run (a different -w file or subenum version); start a new scan instead", target)
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
		s.diff = &differ{previous: previous.names, current: map[string]struct{}{}, firstSeen: previous.firstSeen, lastSeen: previous.lastSeen}
		if f.diffRecords && !s.diff.withRecords(previous, s.in.recordTypes) {
			out.Info("Note: -diff-records: %s has no records (text format), so only names are compared; save results with -format jsonl, json or csv", f.diff)
		}
	}
	return true
}

// resultFile is one open -o file and the writer that renders into it.
type resultFile struct {
	path     string
	file     *output.File
	w        *output.Writer
	reported bool // a write error was already reported by Finish
}

// openOutputs creates the -o files and sets up the result writers. Each file
// gets the full current results in its own format; in -diff mode stdout
// carries only the changes, and each file is ready to be the next run's
// -diff input (#84).
func (s *session) openOutputs() bool {
	f := s.f
	writers := []*output.Writer{s.out}
	for _, t := range s.outputs {
		file, err := output.CreateFile(t.path)
		if err != nil {
			s.out.Error("creating output file: %v", err)
			for _, rf := range s.files {
				_ = rf.file.Close(false) // leave no temporary file behind (#212)
			}
			s.files = nil
			return false
		}
		w := s.wire(output.NewFile(file.Writer, f.testMode, t.format))
		s.files = append(s.files, resultFile{path: t.path, file: file, w: w})
		writers = append(writers, w)
	}
	s.out.SetDiff(s.diff != nil)
	// A real run dates what it finds (#420); simulated and lab runs do not,
	// so a seeded run's output stays the same byte for byte.
	stamp := !f.testMode && f.simZone == ""
	var firstSeen map[string]string
	if s.diff != nil {
		firstSeen = s.diff.firstSeen
	}
	runAt := s.a.clock()
	for _, w := range writers {
		if stamp {
			w.SetSeen(runAt, firstSeen)
		}
		// Bare names when piped or -silent (no "Found:" banner), human-friendly
		// on a terminal.
		w.SetPlain(f.silent || !isTerminal(s.a.stdout))
		w.SetQuiet(f.silent)
		w.SetShowRecords(f.showRecords)
		w.SetSeed(f.seed)
		w.SetTakeoverColumn(dns.HintsTakeover(s.in.recordTypes))
		w.SetSourcesColumn(true)
		w.SetTargetColumn(f.domainList != "")
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
	// JSON diagnostics are for machines, like a piped stderr: progress events
	// only when -progress is given explicitly (#198).
	if !isTerminal(s.a.stderr) || s.out.LogJSON() {
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
	if s.a.signals != nil {
		sigCh = s.a.signals // tests deliver an interrupt on any OS
	}
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	if s.a.signalReady != nil {
		close(s.a.signalReady)
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

// emitResult writes one found name: to the -o files and to stdout, or under
// -diff to stdout only when it changed. Names restored from a -resume state
// were already written.
func (s *session) emitResult(ev scan.Event, permutation bool) {
	if s.restored[ev.Result.Subdomain] {
		s.refound.add(ev.Result)
		return
	}
	res := output.Result{Result: ev.Result, Permutation: permutation, Sources: candidates.FromPermute, Target: s.target}
	switch {
	case ev.Followed:
		res.Sources = candidates.FromRecords // a found name's record named it (#432)
	case !permutation:
		res.Sources = s.cands.SourcesOf(res.Subdomain)
	}
	for _, src := range res.Sources {
		s.foundBy[src]++
	}
	s.targetResults.add(res)
	if res.Takeover != "" {
		s.takeovers = append(s.takeovers, res)
	}
	for _, rf := range s.files {
		rf.w.Emit(res)
	}
	if s.diff == nil {
		s.out.Emit(res)
		return
	}
	if change, previous := s.diff.observe(res.Subdomain, res.Records, res.Partial); change != "" {
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
	s.status = make([]report.Status, n)
	s.results = make([]targetResult, n)
	s.runs = make([]resultLog, n)
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
			s.out.Info("  %-8s %s", s.status[i].Label(), target)
		}
	}
}

// scanOneTarget runs target's main pass and its -permute pass, after
// restoring what an interrupted run saved for it. It reports whether to go
// on: after a reliability abort the resolver is overloaded, so the remaining
// targets are skipped rather than sent to it too (#82).
func (s *session) scanOneTarget(ctx context.Context, i int, target string) (next bool) {
	out := s.out
	out.SetTarget(target) // JSON diagnostics name it (#198)
	defer out.SetTarget("")
	s.target = target
	if len(s.targets) > 1 {
		out.Info("=== [%d/%d] %s ===", i+1, len(s.targets), target)
	}
	entries, duplicates, skipped := s.words.For(target)
	if n := s.words.Suffixed(target); n > 0 && s.f.hostsFile == "" {
		out.Info("Note: %d wordlist entries ended in %s; used them as prefixes", n, target)
	}
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
		reason := "no valid wordlist entries"
		if s.f.hostsFile != "" {
			reason = "no -hosts names under this target"
		}
		out.Error("%s for %s", reason, target)
		s.anyFailed = true
		s.status[i] = report.StatusFailed
		s.results[i] = targetResult{failed: true, err: reason}
		s.failedTargets++
		return true
	}
	// A resumed run re-emits these results; their records are needed only
	// when the output shows them, -diff compares them (#183), or a resume
	// follows them again (-follow-records, #432).
	s.targetResults = resultLog{full: s.format != output.FormatText || s.f.showRecords || s.diff != nil || s.f.followRecs}
	s.entryDigests[i] = entryDigest(entries)
	// Restored names are per target: nested -dL targets can both find a
	// name, and each reports it (#408).
	s.restored = map[string]bool{}
	saved := s.resume.target(target)
	// Passive sources (-ct, -sources) propose names; each is still looked up
	// like a wordlist entry (#130, #193). One set of the entries serves
	// every source and the zone transfer (#248).
	cands := candidates.New(target, entries, s.seeds)
	s.cands, s.foundBy = cands, map[string]int{}
	// A target -exclude rules out is refused by the scan's preflight; it gets
	// no passive lookup and no zone transfer before that either (#372).
	inScope := !scan.TargetOutOfScope(s.in.excludes, target)
	var sourceInfo []targetSource
	if inScope {
		sourceInfo = passiveNames(ctx, s.in.sources, target, saved, out, s.a.sourceURLs)
	}
	for _, src := range sourceInfo {
		added := cands.Add(src.Source, src.Names)
		if src.Fetched {
			out.Info("%s", passive.AddedLine(passive.Labels[src.Source], len(src.Names), target, added))
		}
	}
	var axfrInfo targetAXFR
	if s.f.axfr && inScope {
		// Transferred names are candidates like -ct's: each is still looked
		// up, so only names that resolve are reported (#85).
		axfrInfo = zoneTransfer(ctx, s.f, s.a.transferPort(), target, saved, out, scan.Excluder(s.in.excludes))
		added := cands.Add(candidates.AXFR, axfrInfo.names)
		if len(axfrInfo.allowed) > 0 {
			out.Info("%s", passive.AddedLine("Zone transfer", len(axfrInfo.names), target, added))
		}
	}
	entries, seeds := cands.Entries(), cands.Seeds()
	pass := scanPass{domain: target, entries: entries, maxQueries: s.f.maxQueries}
	if s.deepWords != nil {
		// The name-length limit is the target's, as for -w; a label too
		// long under a deeper parent fails its lookup like any other.
		pass.deepEntries, _, _ = s.deepWords.For(target)
	}
	var mainSaved *resumePass
	restoredHits := 0 // permutation results restored from the state
	if saved != nil {
		mainSaved, restoredHits = s.restoreTarget(saved)
		if saved.Done {
			out.Info("%s was finished before the run stopped; %d results restored", target, len(saved.Results))
			// The report keeps what the finished run found (#315).
			res := targetResult{done: true, final: mainSaved.event(), sources: sourceInfo, axfr: axfrInfo, foundBy: s.foundBy}
			if s.f.permute {
				res.permutation = finishedPermutation(permuteInput{target: target, entries: entries, found: s.targetResults.mainPassNames(),
					seeds: seeds, prev: saved.Permute, restoredHits: restoredHits})
			}
			s.results[i] = res
			s.runs[i] = s.targetResults
			s.anyDone = true
			s.status[i] = report.StatusOK
			return true
		}
		if saved.MainDone {
			out.Info("%s finished its main pass before the run stopped; %d results restored", target, len(saved.Results))
		} else {
			pass.resumeFrom, pass.resumeNames = saved.RootDone, s.targetResults.mainPassNames()
			if s.f.followRecs {
				pass.resumeFollow = recordTargets(s.targetResults.results())
			}
			out.Info("Resuming %s at wordlist entry %d of %d (%d results restored)", target, saved.RootDone, len(entries), len(saved.Results))
		}
	}
	var res targetResult
	if saved != nil && saved.MainDone {
		// Scanning it again would re-expand every saved parent under
		// -recursive, and a name it found anew would change the permutation
		// candidates the saved position indexes (#358).
		res = targetResult{done: true, final: mainSaved.event()}
	} else {
		res = s.mainPass(ctx, pass, mainSaved)
	}
	// -permute: a second pass over permutations of what was found (#72),
	// skipped after an interrupt, a resolver abort or a spent time budget. Its seeds are the
	// main pass's names only, so a resumed pass rebuilds the same
	// candidate list, and it resumes from its own position (#107).
	if s.f.permute && res.done && !res.unfinished() && s.signalCode.Load() == 0 {
		p := permuteInput{target: target, entries: entries, found: s.targetResults.mainPassNames(), seeds: seeds, restoredHits: restoredHits}
		if saved != nil {
			p.prev = saved.Permute
		}
		s.refound = refoundCount{}
		res.permutation = runPermutationPass(ctx, s, p)
		if p := res.permutation; p != nil && s.refound.names > 0 {
			p.found -= int(s.refound.names)
			if p.pass.done {
				p.pass.final = withoutRefound(p.pass.final, s.refound)
			}
		}
		if p := res.permutation; p != nil && p.pass.failed {
			res.failed = true
		}
	}
	res.sources = sourceInfo
	res.axfr = axfrInfo
	res.foundBy = s.foundBy
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
	mainSaved = &resumePass{RootDone: saved.RootDone, Stats: saved.Stats, Processed: saved.Processed, Total: saved.Total, Found: int64(len(saved.Results) - restoredHits),
		Pending: saved.Pending}
	return mainSaved, restoredHits
}

// mainPass scans a target's wordlist; saved is its state from an
// interrupted run, if any.
func (s *session) mainPass(ctx context.Context, p scanPass, saved *resumePass) targetResult {
	if saved != nil {
		left, ok := remainingBudget(s.f.maxQueries, saved.Processed)
		if !ok {
			s.out.Info("%s: the -max-queries budget of %d was spent before the run stopped", p.domain, s.f.maxQueries)
			return targetResult{done: true, final: saved.event()}
		}
		p.maxQueries = left
		saved.handOverPending(&p, s.f.retryIncon)
	}
	s.refound = refoundCount{}
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
	s.status[i] = report.StatusOK
	switch {
	case res.failed:
		s.status[i] = report.StatusFailed
		s.failedTargets++
	case s.signalCode.Load() != 0:
		s.status[i] = report.StatusInterrupted
	}
	if res.resolverAbort && i < len(s.targets)-1 {
		s.out.Error("resolver %s looks overloaded; skipping the %d remaining targets (use -no-abort to continue)", dns.DisplayServer(s.f.dnsServer), len(s.targets)-1-i)
		for j := i + 1; j < len(s.targets); j++ {
			s.status[j] = report.StatusSkipped
			s.failedTargets++
		}
		return false
	}
	return true
}

// inconclusiveNames returns every finished pass's names whose lookup is
// still a timeout, refusal or failure, sorted and deduplicated (#217).
func (s *session) inconclusiveNames() []string {
	var names []string
	for _, res := range s.results {
		if res.done {
			names = append(names, res.final.Stats.Inconclusive...)
		}
		if p := res.permutation; p != nil && p.pass.done {
			names = append(names, p.pass.final.Stats.Inconclusive...)
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

// stoppedEarly reports whether a pass ended with candidates left that a
// resume can still test: -max-duration ran out, or the reliability guard
// aborted it. Such a run ends without a signal, but is saved like an
// interrupted one (#294).
func (s *session) stoppedEarly() bool {
	for _, res := range s.results {
		if res.unfinished() || (res.permutation != nil && res.permutation.pass.unfinished()) {
			return true
		}
	}
	return false
}

// samePath reports whether a and b name one file, however each is spelled
// (x and ./x, a relative and an absolute path, another case on Windows), so
// a -diff baseline that is also an -o file is recognised (#342).
func samePath(a, b string) bool {
	if a == b {
		return true
	}
	ia, errA := os.Stat(a)
	ib, errB := os.Stat(b)
	if errA == nil && errB == nil {
		return os.SameFile(ia, ib)
	}
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA != nil || errB != nil {
		return false
	}
	// Files that do not exist yet: Windows and macOS file systems ignore
	// case by default (#378).
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return strings.EqualFold(absA, absB)
	}
	return absA == absB
}

// finish saves or removes the resume state, writes the run-quality report
// and the -stats and -sarif files, closes the structured output and returns
// the exit code. The deferred -o file close in runWith runs after it.
func (s *session) finish(ctx context.Context) int {
	f, out := s.f, s.out
	logPoolHealth(s.in.pool, out)

	if s.signalCode.Load() != 0 || s.stoppedEarly() {
		// With -diff and -o on one file, the partial results must not replace
		// the baseline the resumed run compares against; the saved state holds
		// them, and the resumed run writes them to the -o file (#297).
		if saveResumeState(s) && f.diff != "" && slices.ContainsFunc(s.files, func(rf resultFile) bool { return samePath(rf.path, f.diff) }) {
			s.keepBaseline = true
			out.Info("Leaving %s unchanged: it is the -diff baseline for the resumed run, which writes the full results", f.diff)
		}
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
	}
	for _, rf := range s.files {
		rf.w.Summary(summary)
	}
	out.Summary(summary)
	if f.statsFile != "" {
		if err := output.WriteSummaryFile(f.statsFile, summary); err != nil {
			out.Error("writing -stats file: %v", err)
			s.fileErr = true
		}
	}
	if f.inconFile != "" && s.anyDone {
		if err := output.WriteNamesFile(f.inconFile, s.inconclusiveNames()); err != nil {
			out.Error("writing -inconclusive file: %v", err)
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
	started := out.Started() || slices.ContainsFunc(s.files, func(rf resultFile) bool { return rf.w.Started() })
	if s.anyDone || started {
		for i := range s.files {
			if err := s.files[i].w.Finish(); err != nil {
				out.Error("writing output file %s: %v", s.files[i].path, err)
				s.files[i].reported = true
				s.fileErr = true
			}
		}
		_ = out.Finish() // stdout only: its write errors are not reported
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
