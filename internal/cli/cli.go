// subenum - A Go-based CLI tool for subdomain enumeration.
// Copyright (C) 2026 TM Hospitality Strategies
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.
//
// For authorized use only. Only scan domains you own or have explicit
// written permission to test.

// Package cli is the subenum command: flag parsing, the per-run session and
// its subsystems (config, diff, resume, permute, passive sources, labs, MCP).
// The repository root holds only the main package that calls Main.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/TMHSDigital/subenum/internal/cliargs"
	"github.com/TMHSDigital/subenum/internal/dns"
	"github.com/TMHSDigital/subenum/internal/output"
	"github.com/TMHSDigital/subenum/internal/scan"
	"github.com/TMHSDigital/subenum/internal/validate"
	"github.com/TMHSDigital/subenum/internal/wordlist"
)

// The program's name and the resolver used when -dns-server is not given.
const (
	ProgramName      = "subenum"
	DefaultDNSServer = validate.DefaultDNSServer

	// highConcurrency is the -t above which the CLI warns (#58).
	highConcurrency = 10000
)

// Exit codes, documented in the README and in -h (#82). A signal exits with
// the shell convention 128+signum: 130 for SIGINT, 143 for SIGTERM.
const (
	exitOK      = 0
	exitFailure = 1 // a scan, the wordlist, the domain list or the output file failed
	exitUsage   = 2 // invalid flags or arguments
	exitPartial = 3 // -dL: some targets failed while others completed
	exitChanges = 4 // -diff: names were added or removed (or, with -diff-records, changed) since the previous run; subenum diff: the files differ
)

const exitCodesHelp = `Exit codes:
  0    success
  1    a scan, the wordlist, the domain list or the output file failed
  2    invalid flags or arguments
  3    -dL: some targets failed while others completed
  4    -diff: names were added or removed (or, with -diff-records, changed) since the previous run; subenum diff: the files differ
  130  interrupted (SIGINT, Ctrl+C); partial results are kept (in the resume
       state when the -o file is also the -diff baseline, left unchanged)
  143  terminated (SIGTERM); partial results are kept as for 130
`

// Version is the release identifier, passed to Main by the main package,
// where Makefile, CI and the Dockerfile set it with
// -ldflags "-X main.Version=$(git describe --tags --dirty)". When it is
// empty (go install, plain go build), the module version from the build info
// is used, so there is no hand-maintained copy to drift between releases.
var Version = ""

// resolveVersion returns Version, else the main module version recorded by
// go install (for example v0.7.0), else "dev".
func resolveVersion() string {
	if Version != "" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

// formatVersion trims a leading "v" so a tag like v0.7.0 does not print as vv0.7.0.
func formatVersion() string {
	v := resolveVersion()
	if v == "dev" {
		return ProgramName + " dev"
	}
	return ProgramName + " v" + strings.TrimPrefix(v, "v")
}

// Main runs the command with the process's arguments and standard streams
// and returns its exit code. version is the build's -X main.Version value,
// empty when none was injected.
func Main(version string) int {
	if version != "" {
		Version = version
	}
	return run()
}

// cliFlags holds all parsed command-line flag values.
type cliFlags struct {
	tui          bool
	printConfig  bool
	dryRun       bool          // -dry-run: print the plan, scan nothing (#192)
	wordlists    wordlistPaths // -w, repeatable (#199)
	hostsFile    string        // -hosts: full host names to resolve instead of a wordlist (#351)
	domainList   string
	concurrency  int
	timeoutMs    int
	dnsServer    string
	verbose      bool
	showVersion  bool
	showProgress bool
	silent       bool   // -silent: results only on stdout, errors only on stderr (#128)
	ct           bool   // -ct: seed from Certificate Transparency logs (#130)
	axfr         bool   // -axfr: try a zone transfer from each name server (#85)
	nsecWalk     bool   // -nsec-walk: list a plain-NSEC zone by walking its chain (#437)
	sources      string // -sources: passive sources to seed candidates from (#193)
	testMode     bool
	testHitRate  int
	seed         uint64
	simZone      string // -simulate-zone: lab scenario served by a local DNS server (#76)
	outputs      outputSpecs
	attempts     int
	retries      int
	force        bool
	format       string
	logFormat    string // -log-format: text or json diagnostics on stderr (#198)
	showRecords  bool
	rate         int
	recordTypes  string
	recursive    bool
	depth        int
	deepWords    wordlistPaths // -recursive-w: the labels tried below depth 1 (#403)
	followRecs   bool          // -follow-records: test in-scope CNAME, MX, NS and HTTPS targets (#432)
	srv          bool          // -srv: look up the built-in _service._proto names (#419)
	ptr          bool          // -ptr: reverse-look up the found public addresses (#436)
	noAbort      bool
	maxQueries   int
	maxDuration  time.Duration // -max-duration: time budget for the whole run (#190)
	autoRate     bool          // -auto-rate: back off instead of aborting (#220)
	retryIncon   bool          // -retry-inconclusive: look inconclusive names up once more (#217)
	inconFile    string        // -inconclusive: write the names still without an answer (#217)
	statsFile    string
	sarifFile    string // -sarif: takeover candidates as SARIF (#129)
	exclude      string
	excludeFile  string
	// -takeover-providers and -takeover-providers-only: extend or replace
	// the takeover-prone provider list (#219).
	providersFile string
	providersOnly bool
	resolvers     string // -r: file of resolver addresses for a pool
	ratePerRes    int    // -rate-per-resolver: per-member cap for the -r pool (#196)
	diff          string // -diff: previous results file to compare against
	diffRecords   bool   // -diff-records: also report names whose records changed (#189)
	stateFile     string // where an interrupted run saves its resume state
	permute       bool   // -permute: second pass over permutations of found names
	seedsFile     string // -seeds: extra permutation seeds (any results format)
}

// runtimeInputs is what a run derives from its flags and environment: the
// values the flags resolve to, the loaded input files and the run-wide
// deadline. Kept apart from cliFlags, which holds only parsed values (#158).
type runtimeInputs struct {
	stdin       io.Reader             // read for a "-" path; nil means os.Stdin
	defaults    *defaultsLoader       // where config-file and env values came from; nil in tests
	maxAttempts int                   // -attempts, or the deprecated -retries
	recordTypes []string              // parsed -type
	excludes    []string              // -exclude and -exclude-file patterns, merged
	pool        *dns.Pool             // built from -r; nil means the single -dns-server
	providers   dns.TakeoverProviders // from -takeover-providers; nil means the built-in list
	sources     []string              // passive sources from -sources and -ct, in passive.Known order
	deadline    time.Time             // when -max-duration runs out; set once the scans start
}

// readLines reads path, or in.stdin when path is "-".
func (in *runtimeInputs) readLines(path string) ([]string, error) {
	if path == wordlist.Stdin && in.stdin != nil {
		return wordlist.ReadLinesFrom(in.stdin)
	}
	return wordlist.ReadLines(path)
}

// scanPass is one scan of one target: its main pass or its -permute pass.
type scanPass struct {
	domain       string
	entries      []string
	extra        []string       // tried after entries, such as source names (#365)
	deepEntries  []string       // -recursive-w entries; nil means entries and extra (#403)
	maxQueries   int            // this pass's -max-queries budget
	resumeFrom   int            // set while resuming (#73)
	resumeNames  []string       // names found before the interrupt
	resumeFollow []string       // -follow-records targets of those names (#432)
	flat         bool           // one level deep: -recursive does not apply (#111)
	retryPrior   []scan.Pending // names the stopped run left for its retry pass (#315)
}

// parseFlags parses args (without the program name). Flags may appear before or
// after the domain; the returned positionals are every non-flag argument.
func parseFlags(args []string) (cliFlags, []string, *flag.FlagSet, error) {
	return parseFlagsWith(args, nil, nil)
}

// parseFlagsWith is parseFlags with applyDefaults run after the flags are
// defined and before the command line is parsed, so config-file and
// environment defaults sit between built-in defaults and explicit flags (#88).
// Parse errors and usage go to stderr; nil means os.Stderr.
func parseFlagsWith(args []string, applyDefaults func(*flag.FlagSet) error, stderr io.Writer) (cliFlags, []string, *flag.FlagSet, error) {
	var f cliFlags
	fs := flag.NewFlagSet(ProgramName, flag.ContinueOnError)
	if stderr != nil {
		fs.SetOutput(stderr)
	}
	fs.BoolVar(&f.tui, "tui", false, "Launch the interactive terminal UI, its form pre-filled from the other flags and the domain argument")
	fs.BoolVar(&f.printConfig, "print-config", false, "Print every setting's effective value and its source (flag, env, config or default), then exit")
	fs.BoolVar(&f.dryRun, "dry-run", false, "Print the plan without scanning: candidates after dedupe and -exclude, query and duration estimates, and the resolver preflight (its only DNS query, also sent to each -r pool resolver); then exit")
	fs.Var(&f.wordlists, "w", "Path to a wordlist `file` (- for stdin); repeat to combine several, deduplicated; omitted: the bundled top-5000 list")
	fs.StringVar(&f.hostsFile, "hosts", "", "A `file` of full host names to resolve instead of a wordlist, one per line (- for stdin); each target looks up only the names under it, names under no target are skipped")
	fs.StringVar(&f.domainList, "dL", "", "File of apex domains to scan, one per line (- for stdin); replaces the <domain> argument")
	fs.IntVar(&f.concurrency, "t", scan.DefaultConcurrency, "Number of concurrent workers")
	fs.IntVar(&f.timeoutMs, "timeout", scan.DefaultTimeoutMs, "DNS lookup timeout in milliseconds")
	fs.StringVar(&f.dnsServer, "dns-server", DefaultDNSServer, "DNS server: ip[:port] (UDP, TCP fallback), tls://host[:853] (DNS over TLS) or https://host/path (DNS over HTTPS)")
	fs.BoolVar(&f.verbose, "v", false, "Enable verbose output")
	fs.BoolVar(&f.showVersion, "version", false, "Show version information")
	fs.BoolVar(&f.showProgress, "progress", true, "Show progress during scanning")
	fs.BoolVar(&f.silent, "silent", false, "Pipeline mode: bare result names on stdout, and only errors (and a simulation warning) on stderr")
	fs.BoolVar(&f.testMode, "simulate", false, "Run in simulation mode without actual DNS queries (for testing)")
	fs.IntVar(&f.testHitRate, "hit-rate", scan.DefaultHitRate, "In simulation mode, percentage of names that resolve (1-100)")
	fs.Uint64Var(&f.seed, "seed", 0, "In simulation mode, seed for reproducible results (0 = random; the seed used is printed)")
	fs.StringVar(&f.simZone, "simulate-zone", "", "Lab mode: answer every query from this scenario file, or a built-in scenario such as lab1 (lab1-lab6, lab7, lab8, lab9), via a local DNS server, so no traffic leaves the machine (see the Labs page)")
	fs.Var(&f.outputs, "o", "Write results to `file` (in addition to stdout); repeat for several files, each in -format or in the format named as a prefix, format:path (jsonl:results.jsonl)")
	fs.IntVar(&f.attempts, "attempts", 0, "Total DNS resolution attempts per subdomain, 1 = no retry (default 1)")
	fs.IntVar(&f.retries, "retries", 0, "Deprecated: use -attempts instead")
	fs.BoolVar(&f.force, "force", false, "Continue scanning even if wildcard DNS is detected")
	fs.StringVar(&f.format, "format", "text", "Output format: text, json, jsonl, or csv")
	fs.StringVar(&f.logFormat, "log-format", "text", "Diagnostics format on stderr: text, or json for one JSON object per line (level, kind, target, message); results on stdout are unchanged")
	fs.BoolVar(&f.showRecords, "show-records", false, "In text format, append each result's records (TYPE=value)")
	fs.IntVar(&f.rate, "rate", 0, "Max DNS queries per second on the wire, all workers combined; counts every record type, retry and wildcard probe (0 = unlimited)")
	fs.StringVar(&f.recordTypes, "type", "A,AAAA", "Comma-separated DNS record types to look up: A, AAAA, CNAME, NS, MX, TXT, SRV, HTTPS (CNAME, NS, SRV and HTTPS aliases also check for takeovers; with NS, a name that fails with SERVFAIL is asked of the zone's own name servers for its delegation)")
	fs.BoolVar(&f.autoRate, "auto-rate", false, "When over 20% of the last 200 lookups fail, halve the query rate and keep going (up to 6 times, down to 5 queries/s) instead of aborting; speed back up once lookups succeed")
	fs.BoolVar(&f.recursive, "recursive", false, "Recursively enumerate subdomains of discovered subdomains")
	fs.IntVar(&f.depth, "depth", 1, "Max recursion depth when -recursive is set (1 = no recursion)")
	fs.BoolVar(&f.srv, "srv", false, "Also look up a built-in list of about 50 service names (_sip._tcp, _autodiscover._tcp, _ldap._tcp, ...) under each target; needs SRV in -type")
	fs.BoolVar(&f.ptr, "ptr", false, "After each scan, look up the PTR records of the public addresses found, and test the names under the target they give, unless already found; the PTR queries are paced by -rate and bounded by -max-queries, -max-duration and -exclude, which also takes reverse zones such as *.2.0.192.in-addr.arpa")
	fs.BoolVar(&f.followRecs, "follow-records", false, "Also test the names under the target that found names' CNAME, MX, NS and HTTPS records point at, once each, unless they are already candidates; they count against -max-queries")
	fs.Var(&f.deepWords, "recursive-w", "Path to a wordlist `file` (- for stdin) of the labels -recursive tries under each name it finds, at depth 2 and below; repeat to combine several; omitted: the -w list")
	fs.BoolVar(&f.noAbort, "no-abort", false, "Do not abort when the resolver failure rate exceeds 20% (warning is still emitted)")
	fs.IntVar(&f.maxQueries, "max-queries", 0, "Max candidate names to test (0 = unlimited); each name sends one query per record type, per attempt")
	fs.DurationVar(&f.maxDuration, "max-duration", 0, "Time budget for the whole run, e.g. 20m (0 = unlimited); then no new names are tested, lookups in flight finish, and the run ends with its report, a degraded verdict and saved state for -resume to continue from")
	fs.BoolVar(&f.retryIncon, "retry-inconclusive", false, "After each scan, look up once more (against -dns-server) every name that timed out, was refused or failed; names it resolves are reported, but not expanded by -recursive")
	fs.StringVar(&f.inconFile, "inconclusive", "", "Write the names still without an answer (timeout, refused, other) to this file, one per line, to rescan with -w")
	fs.StringVar(&f.statsFile, "stats", "", "Write a JSON run-quality report (outcomes, queries sent, verdict) to this file")
	fs.StringVar(&f.sarifFile, "sarif", "", "Write takeover candidates to this file as SARIF 2.1.0, for GitHub code scanning (needs CNAME or NS in -type)")
	fs.StringVar(&f.exclude, "exclude", "", "Comma-separated out-of-scope names and *.parent patterns; never queried or expanded")
	fs.StringVar(&f.excludeFile, "exclude-file", "", "File of out-of-scope names and *.parent patterns, one per line (# comments allowed)")
	fs.StringVar(&f.providersFile, "takeover-providers", "", "File of takeover-prone services, one \"<suffix> <name>\" per line (.example-cdn.net example-cdn; # comments allowed; name - removes a suffix), added to the built-in list for takeover hints")
	fs.BoolVar(&f.providersOnly, "takeover-providers-only", false, "Use only the -takeover-providers file, not the built-in provider list")
	fs.BoolVar(&f.permute, "permute", false, "After each scan, scan permutations of the names found (api -> api-dev, dev-api, dev.api, api2, ...)")
	fs.BoolVar(&f.axfr, "axfr", false, "Try a zone transfer (AXFR) from each of the target's name servers first, and add the names it gives as candidates and -permute seeds; also report a zone that DNSSEC NSEC lets anyone walk")
	fs.BoolVar(&f.nsecWalk, "nsec-walk", false, "When the target's zone is signed with plain DNSSEC NSEC, list it by walking the NSEC chain at its name server first, and add the names as candidates and -permute seeds; one query per name, paced by -rate and bounded by -max-queries, -max-duration and -exclude")
	fs.StringVar(&f.sources, "sources", "", "Comma-separated keyless passive sources whose names become candidates and -permute seeds: ct (Certificate Transparency, crt.sh), wayback (Wayback Machine); one HTTPS request per source and target")
	fs.BoolVar(&f.ct, "ct", false, "Add names from Certificate Transparency logs (crt.sh, one HTTPS request per target, no API key) as candidates and -permute seeds")
	fs.StringVar(&f.seedsFile, "seeds", "", "Results file (any -format) whose names also seed -permute; implies -permute")
	fs.StringVar(&f.stateFile, "state", defaultStateFile, "Where a run that was interrupted, ran out of -max-duration or was aborted saves its state for -resume")
	fs.String("resume", "", "Resume a run that was interrupted, ran out of -max-duration or was aborted, from its state file (no other arguments but the pacing flags -rate, -rate-per-resolver, -t, -timeout, -attempts, -auto-rate, -no-abort and -max-duration)")
	fs.StringVar(&f.diff, "diff", "", "Previous results file (any -format); report only names added or removed since then, and exit 4 when there are changes")
	fs.BoolVar(&f.diffRecords, "diff-records", false, "With -diff, also report names whose records changed (a re-pointed CNAME, moved addresses), compared over the -type record types; needs a json, jsonl or csv -diff file")
	fs.StringVar(&f.resolvers, "r", "", "File of resolvers (ip[:port], tls://host[:port] or https://host/path, one per line) to spread queries over; every hit is re-validated against -dns-server")
	fs.IntVar(&f.ratePerRes, "rate-per-resolver", 0, "With -r, max DNS queries per second sent to each pool resolver; -rate still caps the total (0 = unlimited)")
	fs.Usage = func() {
		w := fs.Output()
		_, _ = fmt.Fprintln(w, "Usage: subenum [-w <wordlist_file>] [options] <domain>")
		_, _ = fmt.Fprintln(w, "       subenum [-w <wordlist_file>] [options] -dL <domains_file>")
		_, _ = fmt.Fprintln(w, "       "+strings.TrimPrefix(diffUsage, "Usage: "))
		_, _ = fmt.Fprintln(w, "       "+strings.TrimPrefix(reportUsage, "Usage: "))
		_, _ = fmt.Fprintln(w, "       subenum mcp [-allow domains] [flags]     (subenum mcp -h for its flags)")
		_, _ = fmt.Fprintln(w, "       subenum completion bash|zsh|fish|powershell")
		_, _ = fmt.Fprintln(w, "       subenum man")
		fs.PrintDefaults()
		_, _ = fmt.Fprint(w, "\n"+exitCodesHelp)
	}
	// A bad config or env value must not hide the command line: -h, -version
	// and -print-config still work, and the caller decides (#116).
	var cfgErr error
	if applyDefaults != nil {
		cfgErr = applyDefaults(fs)
	}
	positionals, err := cliargs.Parse(fs, args)
	if err != nil {
		return f, positionals, fs, err
	}
	return f, positionals, fs, cfgErr
}

// validateArgs checks the domain arguments, before any input file is read,
// so a missing domain is reported first (#120).
func validateArgs(f cliFlags, positionals []string, fs *flag.FlagSet, out *output.Writer) bool {
	if len(positionals) == 0 && f.domainList == "" {
		// Say what is missing before the full flag list (#58).
		out.Error("missing <domain> (or -dL <domains_file>)")
		if !out.LogJSON() { // the usage text is not a JSON line
			fs.Usage()
		}
		return false
	}
	if f.domainList != "" && len(positionals) > 0 {
		out.Error("use either a <domain> argument or -dL, not both")
		return false
	}
	if len(positionals) > 1 {
		out.Error("expected exactly one domain, got %d arguments: %s (use -dL for several)", len(positionals), strings.Join(positionals, " "))
		return false
	}
	// Standard input can only be read once: the first reader drains it and
	// every later one would see an empty file (#378).
	if n := countStdin(f.wordlists.paths); n > 1 {
		out.Error("-w - is given %d times; standard input can only be read once", n)
		return false
	}
	if n := countStdin(f.deepWords.paths); n > 1 {
		out.Error("-recursive-w - is given %d times; standard input can only be read once", n)
		return false
	}
	// A config-file or SUBENUM_* value is a default for recursive runs, so
	// only a command-line -recursive-w needs -recursive.
	if len(f.deepWords.paths) > 0 && !f.deepWords.replace && !f.recursive {
		out.Error("-recursive-w needs -recursive: it names the labels tried under each name found")
		return false
	}
	if readers := stdinReaders(f); len(readers) > 1 {
		out.Error("%s cannot all read standard input (-); it can only be read once, so give all but one a file", strings.Join(readers, ", "))
		return false
	}
	if f.hostsFile != "" {
		// A -w from the config file or SUBENUM_W is a default -hosts replaces.
		switch {
		case f.wordlists.chosen && !f.wordlists.replace:
			out.Error("use either -w or -hosts, not both: -hosts names the hosts to look up instead of a wordlist")
			return false
		case f.recursive:
			out.Error("-recursive cannot be used with -hosts: it scans a wordlist under each name found, and -hosts has none")
			return false
		case f.tui:
			out.Error("-hosts is not available in the TUI")
			return false
		}
	}
	return true
}

// stdinReaders names the flags set to "-", standard input.
func stdinReaders(f cliFlags) []string {
	var names []string
	if f.wordlists.readsStdin() {
		names = append(names, "-w")
	}
	if f.deepWords.readsStdin() {
		names = append(names, "-recursive-w")
	}
	for _, c := range []struct{ name, path string }{
		{"-hosts", f.hostsFile},
		{"-dL", f.domainList},
		{"-r", f.resolvers},
		{"-exclude-file", f.excludeFile},
		{"-takeover-providers", f.providersFile},
	} {
		if c.path == wordlist.Stdin {
			names = append(names, c.name)
		}
	}
	return names
}

// validateFlags checks options after validateArgs has checked the domain
// arguments. configure does that before reading any input files.
func validateFlags(f cliFlags, in *runtimeInputs, positionals []string, fs *flag.FlagSet, out *output.Writer) (string, bool) {
	if f.simZone != "" {
		// Effective values, not just command-line flags: a resolver list or
		// simulation mode from the config file or SUBENUM_* would otherwise
		// send lab queries off the machine (#106).
		for _, c := range []struct {
			name string
			set  bool
		}{
			{"simulate", f.testMode},
			{"dns-server", f.dnsServer != DefaultDNSServer},
			{"r", f.resolvers != ""},
			{"ct", f.ct},                 // an HTTPS request to crt.sh
			{"sources", f.sources != ""}, // HTTPS requests to passive sources
			// -axfr and -nsec-walk are allowed: in lab mode their queries
			// go to the lab server (#434, #437).
		} {
			if c.set || flagSet(fs, c.name) {
				out.Error("-simulate-zone answers from its own local DNS server; it cannot be combined with %s", in.defaults.describe(fs, c.name))
				return "", false
			}
		}
	}
	// Range and resolver checks are shared with the TUI (#80).
	if err := scanOptions(f, in, scanPass{maxQueries: f.maxQueries}, nil).Validate(); err != nil {
		out.ScanError(err.Error())
		return "", false
	}
	if f.diffRecords && f.diff == "" {
		out.Error("-diff-records compares records against a previous results file; add -diff <file>")
		return "", false
	}
	// A service name has SRV records and rarely an address, so without SRV
	// its lookups would find nothing; requiring it keeps the query cost of
	// the extra type visible (#419).
	if f.srv && !slices.Contains(in.recordTypes, "SRV") {
		out.Error("-srv looks up service names, which have SRV records; add SRV to -type (for example -type A,AAAA,SRV)")
		return "", false
	}
	// PTR queries start from the addresses the scan finds (#436).
	if f.ptr && !slices.Contains(in.recordTypes, "A") && !slices.Contains(in.recordTypes, "AAAA") {
		out.Error("-ptr looks up the addresses found, which need A or AAAA in -type (for example -type A,AAAA)")
		return "", false
	}
	if f.ptr && f.testMode {
		out.Info("Note: -ptr sends no reverse lookups in simulation mode")
	}
	if f.concurrency > highConcurrency {
		out.Info("Warning: -t %d is very high; every worker can hold a socket open, and most resolvers rate-limit long before this", f.concurrency)
	}
	if f.domainList != "" {
		return "", true // targets come from loadTargets
	}
	domain, notes, err := validate.NormalizeDomain(positionals[0])
	if err != nil {
		out.Error("%v", err)
		return "", false
	}
	for _, n := range notes {
		out.Info("Note: %s", n)
	}
	return domain, true
}

// loadPool builds the -r resolver pool (#69). It reports its own errors and
// returns the exit code for them: an unreadable file is a failure like any
// other input file, a malformed one a usage error (#120).
func loadPool(f cliFlags, in *runtimeInputs, out *output.Writer) (*dns.Pool, int) {
	if f.resolvers == "" {
		return nil, exitOK
	}
	if f.testMode {
		out.Info("Note: -r is ignored in simulation mode, which sends no DNS queries")
		return nil, exitOK
	}
	lines, err := in.readLines(f.resolvers)
	if err != nil {
		out.Error("reading -r resolver list: %v", err)
		return nil, exitFailure
	}
	pool, err := dns.NewPoolFromLines(lines, time.Duration(f.timeoutMs)*time.Millisecond, f.ratePerRes)
	if errors.Is(err, dns.ErrNoResolvers) {
		err = fmt.Errorf("%s %w", f.resolvers, err)
	}
	if err != nil {
		out.Error("-r: %v", err)
		return nil, exitUsage
	}
	out.Info("Resolver pool: %d resolvers; every hit is re-validated against %s", pool.Size(), dns.DisplayServer(f.dnsServer))
	return pool, exitOK
}

// logPoolHealth prints each pool resolver's accounting at the end of a run.
func logPoolHealth(pool *dns.Pool, out *output.Writer) {
	if pool == nil {
		return
	}
	out.Info("Resolvers:")
	out.Info("  %-24s %8s %8s %8s %8s %7s %9s %12s", "address", "lookups", "found", "nxdomain", "failed", "benched", "throttled", "contradicted")
	for _, r := range pool.Stats() {
		flag := ""
		if r.Flagged {
			flag = "  FLAGGED: dropped as lying"
		}
		out.Info("  %-24s %8d %8d %8d %8d %7d %9d %12d%s", r.Addr, r.Lookups, r.Found, r.NXDomain, r.Failed, r.Benched, r.Throttled, r.Contradicted, flag)
	}
}

// loadExcludes merges the -exclude list and the -exclude-file lines (#87).
// Patterns are validated with the other options.
func loadExcludes(f cliFlags, in *runtimeInputs) ([]string, error) {
	var patterns []string
	for _, p := range strings.Split(f.exclude, ",") {
		if p = strings.TrimSpace(p); p != "" {
			patterns = append(patterns, p)
		}
	}
	if f.excludeFile == "" {
		return patterns, nil
	}
	lines, err := in.readLines(f.excludeFile)
	if err != nil {
		return nil, err
	}
	for _, line := range lines {
		if !wordlist.IsComment(line) {
			patterns = append(patterns, strings.TrimSpace(line))
		}
	}
	return patterns, nil
}

// loadTakeoverProviders reads the -takeover-providers file (#219). Without
// one it returns nil, the built-in list.
func loadTakeoverProviders(f cliFlags, in *runtimeInputs) (dns.TakeoverProviders, error) {
	if f.providersFile == "" {
		if f.providersOnly {
			return nil, errors.New("-takeover-providers-only needs a -takeover-providers file")
		}
		return nil, nil
	}
	lines, err := in.readLines(f.providersFile)
	if err != nil {
		return nil, fmt.Errorf("reading -takeover-providers file: %w", err)
	}
	providers, err := dns.ParseTakeoverProviders(lines, f.providersOnly)
	if err != nil {
		return nil, fmt.Errorf("-takeover-providers %s: %w", f.providersFile, err)
	}
	return providers, nil
}

// loadTargets returns the apex domains to scan: the single positional domain,
// or the entries of the -dL file ("-" for stdin). Blank lines, # comments and
// duplicates are skipped; invalid domains are reported and skipped.
func loadTargets(f cliFlags, in *runtimeInputs, domain string, out *output.Writer) ([]string, bool) {
	if f.domainList == "" {
		return []string{domain}, true
	}
	lines, err := in.readLines(f.domainList)
	if err != nil {
		out.Error("reading domain list: %v", err)
		return nil, false
	}
	var targets []string
	seen := make(map[string]bool)
	for _, line := range lines {
		if wordlist.IsComment(line) {
			continue
		}
		d, notes, err := validate.NormalizeDomain(line)
		if err != nil {
			out.Info("Skipping invalid domain %q in %s: %v", strings.TrimSpace(line), f.domainList, err)
			continue
		}
		for _, n := range notes {
			out.Info("Note: %s", n)
		}
		if !seen[d] {
			seen[d] = true
			targets = append(targets, d)
		}
	}
	if len(targets) == 0 {
		out.Error("domain list %s has no valid domains", f.domainList)
		return nil, false
	}
	return targets, true
}

// outputSpecs is the repeatable -o flag (#334). Each -o adds a results file,
// written in -format or in the format its "format:" prefix names, so one run
// can save bare names for the next tool and JSONL for the next -diff.
//
// A config-file or SUBENUM_O value is a default: it is replaced, not added
// to, by a later source or by the first -o on the command line.
type outputSpecs struct {
	specs   []string
	replace bool // the current specs are a default; the next Set replaces them
}

func (o *outputSpecs) String() string {
	if o == nil {
		return ""
	}
	return strings.Join(o.specs, ",")
}

// Set adds a file. An empty value adds nothing, so -o "" still means none.
func (o *outputSpecs) Set(v string) error {
	if o.replace {
		o.specs, o.replace = nil, false
	}
	if v != "" {
		o.specs = append(o.specs, v)
	}
	return nil
}

// markDefault records that the current specs came from the config file or
// the environment rather than the command line.
func (o *outputSpecs) markDefault() { o.replace = true }

// list returns the specs, for -print-config.
func (o *outputSpecs) list() []string { return o.specs }

// describe names the -o files for notices: the paths, comma-separated.
func (o *outputSpecs) describe() string {
	paths := make([]string, len(o.specs))
	for i, spec := range o.specs {
		_, paths[i] = splitOutputSpec(spec)
	}
	return strings.Join(paths, ", ")
}

// splitOutputSpec splits an -o value into its format prefix, "" for none,
// and its path. Only a format name counts as a prefix, so a Windows drive
// letter (C:\results.txt) is part of the path.
func splitOutputSpec(spec string) (format, path string) {
	prefix, rest, ok := strings.Cut(spec, ":")
	if ok && rest != "" && slices.Contains(append(output.Formats(), "ndjson"), strings.ToLower(prefix)) {
		return prefix, rest
	}
	return "", spec
}

// outputTarget is one -o file and the format it is written in.
type outputTarget struct {
	path   string
	format output.Format
}

// parseOutputs resolves the -o values; a file without a prefix takes def,
// the -format of stdout. The same file given twice, however it is spelled,
// is refused: both would replace one file (#378).
func parseOutputs(specs []string, def output.Format) ([]outputTarget, error) {
	targets := make([]outputTarget, 0, len(specs))
	for _, spec := range specs {
		name, path := splitOutputSpec(spec)
		format := def
		if name != "" {
			var err error
			if format, err = output.ParseFormat(name); err != nil {
				return nil, err
			}
		}
		for _, t := range targets {
			if samePath(t.path, path) {
				return nil, fmt.Errorf("-o %s and -o %s name the same file; each -o needs its own", t.path, path)
			}
		}
		targets = append(targets, outputTarget{path: path, format: format})
	}
	return targets, nil
}

// checkOutputFiles refuses two outputs that name the same file: the last one
// written would replace the others (#378, #395). -state is compared with every
// output so an interrupted run cannot lose its resume state. -diff is compared
// with the other non--o reports, but -o X -diff X is allowed (#297).
func checkOutputFiles(f cliFlags, outputs []outputTarget) error {
	type named struct{ flag, path string }
	var files []named
	for _, t := range outputs {
		files = append(files, named{"-o", t.path})
	}
	for _, n := range []named{
		{"-state", f.stateFile},
		{"-inconclusive", f.inconFile},
		{"-stats", f.statsFile},
		{"-sarif", f.sarifFile},
		{"-diff", f.diff},
	} {
		if n.path == "" {
			continue
		}
		for _, prev := range files {
			if n.flag == "-diff" && prev.flag == "-o" {
				continue
			}
			if samePath(prev.path, n.path) {
				return fmt.Errorf("%s %s and %s %s name the same file; give each its own", prev.flag, prev.path, n.flag, n.path)
			}
		}
		files = append(files, n)
	}
	return nil
}

// isTerminal reports whether w is a character device (a terminal) rather than
// a pipe, file or in-memory buffer.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// flagSet reports whether the named flag was given on the command line.
func flagSet(fs *flag.FlagSet, name string) bool {
	set := false
	fs.Visit(func(fl *flag.Flag) { set = set || fl.Name == name })
	return set
}

func logVerboseStart(f cliFlags, domain string, maxAttempts int, out *output.Writer) {
	out.Info("Starting %s", formatVersion())
	if f.testMode {
		out.Info("Mode: SIMULATION (no actual DNS queries)")
		out.Info("Simulated hit rate: %d%%", f.testHitRate)
	} else {
		out.Info("Mode: LIVE DNS RESOLUTION")
	}
	out.Info("Target domain: %s", domain)
	switch {
	case f.hostsFile != "":
		out.Info("Hosts: %s", f.hostsFile)
	case len(f.wordlists.paths) == 0:
		out.Info("Wordlist: %s", defaultWordlistName(f))
	default:
		out.Info("Wordlist: %s", f.wordlists.describe())
	}
	out.Info("Concurrency: %d workers", f.concurrency)
	out.Info("Timeout: %d ms", f.timeoutMs)
	out.Info("Attempts: %d", maxAttempts)
	if !f.testMode {
		out.Info("DNS Server: %s", dns.DisplayServer(f.dnsServer))
	}
	if len(f.outputs.specs) > 0 {
		out.Info("Output file: %s", f.outputs.describe())
	}
	out.Info("---")
}

func logVerboseDone(ev scan.Event, f cliFlags, out *output.Writer) {
	out.Info("Processed %d subdomain prefixes", ev.Processed)
	if len(f.outputs.specs) > 0 {
		out.Info("Results written to: %s", f.outputs.describe())
	}
	if f.testMode {
		out.Info("\nNOTE: Results were simulated and no actual DNS queries were performed.")
		out.Info("This mode is intended for educational and testing purposes only.")
	}
}

func logScanBreakdown(domain string, ev scan.Event, out *output.Writer) {
	s := ev.Stats
	out.Info("Scan complete for %s", domain)
	out.Info("  resolved:  %d", s.Found)
	out.Info("  nxdomain:  %d", s.NXDomain)
	out.Info("  timeout:   %d", s.Timeout)
	out.Info("  refused:   %d", s.Refused)
	out.Info("  other:     %d", s.Other)
	out.Info("  wildcard-filtered: %d", s.WildcardFiltered)
	if s.Excluded > 0 {
		out.Info("  excluded (out of scope): %d", s.Excluded)
	}
	if s.PoolHits > 0 {
		out.Info("  pool hits: %d (confirmed by the trusted resolver: %d, not confirmed: %d)", s.PoolHits, s.Confirmed, s.Unconfirmed)
	}
	if s.Takeover > 0 {
		out.Info("  takeover candidates: %d (DNS-only hints; verify each by hand)", s.Takeover)
	}
	if s.ParentChecks > 0 {
		out.Info("  asked the zone's name servers: %d SERVFAIL names (%d queries)", s.ParentChecks, s.ParentQueries)
	}
	if s.Internal > 0 {
		out.Info("  internal addresses: %d (public names answering with loopback, private, link-local or CGNAT addresses)", s.Internal)
	}
	if s.Partial > 0 {
		out.Info("  partial answers: %d (found names a requested record type got no answer for; records may be missing)", s.Partial)
	}
	if s.RateBackoffs > 0 {
		out.Info("  rate back-offs: %d (ended at %d queries/s)", s.RateBackoffs, s.FinalRate)
	}
	if s.Retried > 0 {
		out.Info("  retried inconclusive: %d (answered on retry: %d)", s.Retried, s.Recovered)
	}
}

// runArgs is the process environment a run reads: the arguments after the
// program name and the standard streams. Tests pass their own, so they do
// not swap os.Args, os.Stdin, os.Stdout and os.Stderr (#158).
type runArgs struct {
	args   []string
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer

	// Test seams, zero in production (#266). Being per run rather than
	// package variables, they let tests that set them run in parallel.

	// signals, when set, receives signals in place of a fresh channel, so a
	// test can interrupt a run in-process on Windows too.
	signals chan os.Signal
	// signalReady, when set, is closed once the signal handler is installed.
	signalReady chan struct{}
	// sourceURLs replace passive sources' endpoints, by source name.
	sourceURLs map[string]string
	// axfrPort is the port zone transfers are requested on; "" is 53.
	axfrPort string
	// now is the clock that dates results' first_seen and last_seen
	// (#420); nil is time.Now.
	now func() time.Time
}

// clock returns the time results are dated with.
func (a runArgs) clock() time.Time {
	if a.now == nil {
		return time.Now()
	}
	return a.now()
}

// transferPort is the port -axfr asks name servers on.
func (a runArgs) transferPort() string {
	if a.axfrPort == "" {
		return "53"
	}
	return a.axfrPort
}

func run() int {
	return runWith(runArgs{args: os.Args[1:], stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr})
}

// runEnding is what decides a finished run's exit code.
type runEnding struct {
	signal        int32 // 128+signum once a signal arrived, else 0
	fileErr       bool  // writing an output, -stats or -sarif file failed
	targets       int
	failedTargets int  // targets that failed or were skipped
	anyFailed     bool // a scan, wordlist or pass failed
	changes       int  // -diff: names added, removed or changed
}

// exitCode applies the precedence: a signal (shell convention 128+signum:
// partial results were flushed, but callers can tell an interrupted scan
// apart), then a file error, then a partial -dL failure, then any failure,
// then -diff changes.
func (e runEnding) exitCode() int {
	switch {
	case e.signal != 0:
		return int(e.signal)
	case e.fileErr:
		return exitFailure
	case e.targets > 1 && e.failedTargets > 0 && e.failedTargets < e.targets:
		return exitPartial
	case e.anyFailed:
		return exitFailure
	case e.changes > 0:
		return exitChanges
	}
	return exitOK
}

// scanOptions maps the CLI flags onto the scan options the TUI also builds,
// so both front ends share one validator and one Config builder (#80).
func scanOptions(f cliFlags, in *runtimeInputs, p scanPass, logf dns.Logf) scan.Options {
	recursive, depth := f.recursive, f.depth
	if p.flat {
		recursive, depth = false, 1
	}
	dnsServer := f.dnsServer
	if normalized, err := validate.NormalizeDNSServer(dnsServer); err == nil {
		dnsServer = normalized
	}
	return scan.Options{
		Config: scan.Config{
			Domain:           p.domain,
			Entries:          p.entries,
			Extra:            p.extra,
			RecursiveEntries: p.deepEntries,
			Concurrency:      f.concurrency,
			Timeout:          time.Duration(f.timeoutMs) * time.Millisecond,
			DNSServer:        dnsServer,
			Simulate:         f.testMode,
			HitRate:          f.testHitRate,
			Seed:             f.seed,
			Attempts:         in.maxAttempts,
			Force:            f.force,
			Types:            in.recordTypes,
			Recursive:        recursive,
			Depth:            depth,
			// The -permute pass tests variants, not what records name.
			FollowRecords: f.followRecs && !p.flat,
			ResumeFollow:  p.resumeFollow,
			Rate:          f.rate,
			AutoRate:      f.autoRate,
			MaxQueries:    p.maxQueries,
			Deadline:      in.deadline,
			Exclude:       in.excludes,
			ResumeFrom:    p.resumeFrom,
			// The retry pass belongs to the scan, so a resumed scan runs it
			// too, for the names the stopped run left it as well (#315).
			RetryInconclusive: f.retryIncon,
			RetryPrior:        p.retryPrior,
			// Only the -inconclusive file reads the names (#300).
			ListInconclusive:  f.inconFile != "",
			TakeoverProviders: in.providers,
			// Names found before an interrupt still need their children
			// expanded.
			ResumeParents: p.resumeNames,
			Pool:          in.pool,
			ZoneServer:    labZoneServer(f),
			NoAbort:       f.noAbort,
			Verbose:       f.verbose,
			Logf:          logf,
		},
		MaxDuration:     f.maxDuration,
		RatePerResolver: f.ratePerRes,
	}
}

// labZoneServer is where a lab run sends the queries meant for the zone's
// name servers: its local server, so they never leave the machine (#406).
// Outside a lab it is "", and they go to the name servers' addresses.
func labZoneServer(f cliFlags) string {
	if f.simZone == "" {
		return ""
	}
	return f.dnsServer
}

// targetResult is how one domain's scan ended.
type targetResult struct {
	done          bool       // EventDone arrived
	failed        bool       // counts as a failure for the exit code
	resolverAbort bool       // the reliability guard aborted it
	err           string     // first error message, if any
	final         scan.Event // the EventDone, when done
	permutation   *permutationResult
	ptr           *ptrResult     // -ptr pass, when it ran (#436)
	sources       []targetSource // -ct and -sources names, kept for the report and resume state
	axfr          targetAXFR     // -axfr zone transfer, kept for the report and resume state
	foundBy       map[string]int // results per source that proposed them, for the report (#273)
}

// unfinished reports whether the pass stopped with candidates untested, on
// the -max-duration budget or a reliability abort (#294).
func (r targetResult) unfinished() bool {
	return r.resolverAbort || (r.done && r.final.Stats.Expired)
}

// scanTarget runs one pass over a domain and streams its events to the
// session's writer, and each result to emit.
func scanTarget(ctx context.Context, s *session, p scanPass, emit func(scan.Event)) (res targetResult) {
	f, out := s.f, s.out
	// Logf is serialized with the progress line (#36).
	cfg := scanOptions(f, &s.in, p, out.Verbose).Config

	events := make(chan scan.Event, 64)
	go scan.Run(ctx, cfg, events)

	progressStarted := false
	finishProgress := func() {
		if progressStarted {
			out.ProgressDone()
			progressStarted = false
		}
	}
	for ev := range events {
		switch ev.Kind {
		case scan.EventResult:
			emit(ev)
		case scan.EventProgress:
			if f.showProgress && ev.Total > 0 {
				progressStarted = true
				pct := float64(ev.Processed) / float64(ev.Total) * 100
				out.Progress(pct, ev.Processed, ev.Total, ev.Found)
			}
		case scan.EventNotice:
			out.ScanNotice(ev.Notice.String(), ev.Message)
		case scan.EventError:
			if !ev.Fatal {
				// The reliability guard's warning under -no-abort: the scan
				// goes on, so it is neither an error line nor the target's
				// error in the report (#308).
				out.ScanWarning(ev.Message)
				break
			}
			msg := out.ScanError(ev.Message)
			if res.err == "" {
				res.err = msg
			}
			finishProgress()
			// Keep draining: EventDone always follows (#99), Stopped after an
			// early error such as wildcard detection, with Stats after a
			// reliability abort.
		case scan.EventDone:
			finishProgress()
			// The engine says whether the scan failed (#308): a fatal error
			// did, the reliability warning under -no-abort did not.
			res.failed = ev.Failed
			if ev.Stopped {
				// Nothing was scanned: the run failed (or was interrupted)
				// before the candidates, so it does not count as done.
				break
			}
			res.done = true
			res.final = ev
			res.resolverAbort = ev.Stats.Aborted
			logScanBreakdown(p.domain, ev, out)
			if f.verbose {
				logVerboseDone(ev, f, out)
			}
		}
	}
	return res
}

// effectiveAttempts merges the -attempts and deprecated -retries flags. When
// both are set, the one from the higher-precedence source wins (a flag over
// an env value over the config file); both at the same level is an error
// (#116). fromRetries reports that the value came from -retries, so the
// caller can print the deprecation warning.
func effectiveAttempts(attempts, retries int, attemptsSrc, retriesSrc string) (n int, fromRetries bool, err error) {
	// "Given" comes from the source, not the value: 0 is the flag default, and
	// an explicit 0 must reach Options.Validate instead of passing as unset.
	attemptsSet := attemptsSrc != sourceDefault
	retriesSet := retriesSrc != sourceDefault
	if attemptsSet && retriesSet {
		switch ra, rr := sourceRank[attemptsSrc], sourceRank[retriesSrc]; {
		case ra > rr:
			retriesSet = false
		case rr > ra:
			attemptsSet = false
		}
	}

	switch {
	case attemptsSet && retriesSet:
		return 0, false, fmt.Errorf("cannot use both -attempts and -retries; use -attempts only")
	case retriesSet:
		return retries, true, nil
	case attemptsSet:
		return attempts, false, nil
	default:
		return 1, false, nil
	}
}
