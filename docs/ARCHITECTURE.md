---
layout: default
title: Architecture
---

# Architecture

This document describes the architecture of the `subenum` tool, a Go-based command-line utility for subdomain enumeration. It describes responsibilities and names the identifiers involved; for exact signatures see the package docs on pkg.go.dev (for example [`internal/scan`](https://pkg.go.dev/github.com/TMHSDigital/subenum/internal/scan) and [`internal/dns`](https://pkg.go.dev/github.com/TMHSDigital/subenum/internal/dns)) or the source.

## 1. Overview

The `subenum` tool operates through a sequence of steps to discover valid subdomains for a given target domain:

1.  **Initialization**: Parses command-line arguments (flags may appear before or after the domain), normalizes the target domain (or reads a list of targets with `-dL`), and validates the scan options.
2.  **Wordlist Ingestion**: Reads the wordlist once, then normalizes and deduplicates it per target.
3.  **Preflight**: Resolves the target apex once; a resolver that times out, refuses or errors stops the scan before any candidate is sent.
4.  **Wildcard Detection**: Probes random subdomains of the target and keeps their answers as a fingerprint. The scan stops unless `-force` is set; with `-force`, results matching the fingerprint are filtered. Recursive scans also probe each new parent before expanding it.
5.  **Concurrent Resolution**: A dispatcher generates candidate names (`prefix.target`) lazily and feeds a pool of worker goroutines, which resolve each candidate over DNS.
6.  **Output**: Resolved subdomains are printed to stdout (pipe-friendly); all progress, verbose, and diagnostic output goes to stderr.
7.  **Completion**: The tool waits for all lookups to finish, prints a per-outcome breakdown, finalizes structured output and the `-o` file, and exits with a documented exit code.

This architecture is designed to be efficient by performing multiple DNS lookups concurrently, while also providing control over concurrency, timeouts, and the query rate.

### Package Structure

Every package under `internal/` and `pkg/`, summarized from its `// Package` comment:

| Package | Purpose |
| --- | --- |
| `internal/scan` | Runs a scan: validates options, dispatches candidates to a worker pool, filters wildcard answers, grades the run |
| `internal/dns` | Resolves candidate names, classifies lookup outcomes, detects wildcards; transports, resolver pool, rate limiting, takeover hints, simulation |
| `internal/output` | Renders results (text, JSON, JSONL, CSV) to stdout and the `-o` file; run-quality summary, SARIF, ETA |
| `internal/report` | Builds the run-quality report from finished scans, shared by the CLI and the TUI |
| `internal/wordlist` | Reads wordlist files and normalizes their entries into candidate prefixes |
| `internal/validate` | Input validators shared by the CLI and the TUI (domain, resolver address, punycode) |
| `internal/permute` | Generates second-pass candidates from names a scan has already found |
| `internal/ct` | Looks up subdomain names in Certificate Transparency logs through crt.sh |
| `internal/labzone` | Parses `-simulate-zone` scenario files for lab mode |
| `internal/dnsserver` | Scriptable local DNS server backing lab mode and the hermetic tests |
| `internal/dnstest` | Runs `internal/dnsserver` for tests: stopped on cleanup, listen failures fail or skip the test |
| `internal/tui` | Bubble Tea terminal UI |
| `pkg/subenum` | Public API that embeds the same engine in other Go programs |

Files, by role:

```
main.go                        - CLI entry point: run, flag parsing and validation, scanTarget, exit codes
main_session.go                - runWith and the session: per-run state, the -dL target loop, -tui dispatch
main_completion.go             - completion and man subcommands
main_config.go                 - config file and SUBENUM_* environment defaults, -print-config
main_ct.go                     - -ct: Certificate Transparency names as extra candidates
main_diff.go                   - -diff / -diff-records: compare against a previous results file
main_lab.go                    - -simulate-zone: serve a lab scenario on a loopback DNS server
main_permute.go                - -permute / -seeds: the permutation pass
main_resume.go                 - -resume / -state: save and replay an interrupted run
main_summary.go                - assemble the run-quality report (-stats, JSONL summary line)
main_wordlist.go               - readWordlist: the -w file, or the bundled list when -w is not given
internal/scan/options.go       - Options: user-facing settings shared by CLI and TUI (Validate, Config)
internal/scan/runner.go        - Scan engine: Config, Event/EventKind/NoticeKind, Stats, Run
internal/scan/dispatcher.go    - dispatcher: lazy candidate generation, budgets, resume watermark
internal/scan/scope.go         - -exclude patterns (ValidateExcludes, IsExcluded)
internal/scan/settings.go      - Setting tokens in engine messages, rendered per front end (Render, FlagName)
internal/scan/verdict.go       - Run-quality verdicts (Stats.Verdict, VerdictRank)
internal/scan/verify.go        - Verify: re-check names against the trusted resolver (used by -diff)
internal/dns/resolver.go       - NewResolver, ResolveTypes, ResolveDomainWithRetry, Classify,
                                 CheckWildcard, FingerprintWildcard, ParseTypes
internal/dns/transport.go      - UDP (TCP fallback), DNS over TLS and DNS over HTTPS dialers
internal/dns/pool.go           - Pool: the -r resolver pool (health benching, canaries, second opinions)
internal/dns/ratelimit.go      - RateLimiter, WithLimiter (per-wire-query pacing)
internal/dns/takeover.go       - TakeoverProvider, TakeoverHint (dangling or takeover-prone CNAMEs)
internal/dns/simulate.go       - SimulateResolve (seeded synthetic DNS)
internal/output/writer.go      - Thread-safe Writer (results to stdout, diagnostics to stderr)
internal/output/file.go        - File: atomically replaced -o results file
internal/output/summary.go     - Summary / TargetSummary, WriteSummaryFile
internal/output/sarif.go       - WriteSARIF: takeover candidates as SARIF 2.1.0
internal/output/eta.go         - ETA: progress estimate over a sliding window, FormatETA
internal/report/report.go      - New, Target, Finish: the run-quality report
internal/permute/permute.go    - Generate: permutations of found names
internal/ct/ct.go              - Client.Names: crt.sh lookup
internal/labzone/labzone.go    - Load, Parse: lab scenario files
internal/dnsserver/server.go   - Listen: scriptable loopback DNS server
internal/dnstest/dnstest.go    - Start, StartWith, StartTLS: test helpers around dnsserver
internal/validate/validate.go  - DNSServer, Domain, NormalizeDomain, DefaultDNSServer
internal/validate/punycode.go  - IDN to punycode (A-label) conversion
internal/wordlist/reader.go    - ReadLines, Normalize, Build, LoadWordlist
internal/tui/model.go          - Root Bubble Tea model (form -> scan state machine)
internal/tui/form.go           - Config form screen (textinput fields + toggles)
internal/tui/scan_view.go      - Live results screen (viewport + progress bar)
internal/tui/logo.go           - Styled wordmark
internal/tui/config.go         - Session persistence (load/save <user config dir>/subenum/last.json)
pkg/subenum/subenum.go         - Scan, Run, DefaultWords: the embeddable API
tools/wordlist-gen.go          - Standalone wordlist generator
```

## 2. Key Components / Modules

### 2.1. Argument Parsing (`main.go`, `internal/validate`)

*   **Purpose**: This component is responsible for processing the command-line arguments provided by the user when `subenum` is executed. It extracts the target domain (or a `-dL` domain list), the wordlist path, and every scan, output, and tuning option.
*   **Implementation**: `run()` only calls `runWith(runArgs)`, which takes the arguments, stdin, stdout and stderr as injected values so tests can drive the whole CLI in-process. Per-run state lives in a `session` (`main_session.go`) whose methods are the run's phases: `parse`, `configure`, `loadInputs`, `openOutputs`, `scanAll` (which calls `scanOneTarget` per target) and `finish`. `cliFlags` holds only parsed flag values; what the run derives from them (attempts, record types, excludes, the resolver pool, the `-max-duration` deadline) is in `runtimeInputs`, and each pass over a target is a `scanPass`. `runWith` first handles the `completion` and `man` subcommands and `-resume`, then builds a `flag.FlagSet` with `parseFlagsWith`, which binds every flag into a `cliFlags` struct and applies config-file and environment defaults (see section 5). The standard `flag` package stops at the first non-flag argument, so `parseInterspersed` re-parses around each positional; flags written after the domain are honored, and everything after a `--` terminator is positional. `runWith` then:
    *   handles `-tui` (launches `tui.Start`, ignoring other flags), `-print-config` and `-version` first;
    *   parses `-format` (`output.ParseFormat`), `-type` (`dns.ParseTypes`), and merges `-attempts` with the deprecated `-retries` (`effectiveAttempts`);
    *   calls `validateFlags`, which checks that `-w` and a target are present, that a positional domain and `-dL` are not both given, and that `-w` and `-dL` do not both read stdin. Numeric ranges and the resolver address are checked by `scan.Options.Validate`, the same validator the TUI uses. The positional domain is canonicalized with `validate.NormalizeDomain`.
*   **Domain normalization**: `validate.NormalizeDomain` trims and lowercases the input, strips a URL scheme and path, a `:port`, a leading `*.` and a trailing dot (returning a note for each change), converts IDNs to punycode, and checks the result with `validate.Domain`. `validate.DNSServer` checks the resolver: `ip:port`, `tls://host[:port]` or `https://host/path`. Both are shared with the TUI.
*   **Target list (`-dL`)**: `loadTargets` returns either the single positional domain or the entries of the `-dL` file (`-` for stdin). Blank lines, `#` comments and duplicates are skipped; invalid domains are reported and skipped. An empty result is an error.
*   **Interactions**: `scanOptions` maps the parsed flags onto a `scan.Options`; its `Config` method produces the `scan.Config` passed to the scan engine.

### 2.2. Wordlist Processing (`internal/wordlist`)

*   **Purpose**: This component is responsible for reading, sanitizing, validating, and deduplicating the subdomain prefixes from the user-specified wordlist.
*   **Implementation**:
    *   `wordlist.ReadLines` reads every line of a file, or of standard input when the path is `-` (`wordlist.Stdin`). It strips a leading UTF-8 byte order mark and truncates (and drains) absurdly long lines instead of failing.
    *   `wordlist.Normalize` turns one raw line into the prefix that will be queried: trimmed, lowercased, trailing dot removed. Blank lines, `#` comments, and entries that are not valid DNS labels are rejected. Multi-label prefixes such as `dev.api` and service labels such as `_dmarc` are kept.
    *   `wordlist.Build` normalizes all lines for one target domain, preserving first-occurrence order. It reports the number of case-insensitive duplicates and of skipped entries (invalid, or whose full name under the target would exceed 253 characters).
    *   `wordlist.LoadWordlist` combines `ReadLines` and `Build`; the TUI uses it.
*   **Interactions**: The CLI reads the wordlist once with `ReadLines` (stdin can only be read once) before creating the `-o` file, so a bad `-w` path never truncates an existing results file. It then calls `Build` per target, since the name-length limit depends on the domain. The resulting slice becomes `scan.Config.Entries`. Skipped counts are always reported; duplicate counts in verbose mode.

### 2.3. DNS Resolution Engine (`internal/dns`)

*   **Purpose**: This is the core component responsible for performing the DNS lookups for each candidate name and classifying what happened. It also provides wildcard detection and wire-level rate limiting.
*   **Implementation**:
    *   **Resolver and transports**: `dns.NewResolver` builds a `net.Resolver` with `PreferGo: true` whose `Dial` hook always connects to the configured server through a transport chosen from the `-dns-server` value (`dns.Transport`, `internal/dns/transport.go`):
        *   `ip:port` - UDP, with UDP sockets reused between queries; a truncated answer (TC=1) falls back to TCP, which dials per query.
        *   `tls://host[:853]` - DNS over TLS (RFC 7858), over a small pool of reused TLS connections.
        *   `https://host/path` - DNS over HTTPS (RFC 8484), each query sent as an HTTP POST of `application/dns-message`.

        `scan.Run` builds one resolver per scan (unless `Config.Resolver` is set) and reuses it for every lookup; `dns.CloseIdleConnections` releases its pooled connections when the scan ends.
    *   **Resolver pool (`-r`)**: `dns.ParseResolverList` reads the `-r` file (`ip` or `ip:port`, port 53 by default) and `dns.NewPool` builds a `dns.Pool` over it. Candidate lookups go round-robin over the healthy members; the `-dns-server` resolver stays the *trusted* resolver and runs the preflight and wildcard probes. Safeguards:
        *   **Health benching**: over each window of 20 lookups, a member that failed (timeout, refused, other) more than half of them is benched for 30 seconds, then tried again.
        *   **Hit re-validation**: every pool hit is resolved again on the trusted resolver, and the trusted answer is the one reported (`resolveViaPool` in `internal/scan/runner.go`), so a poisoned member cannot inject names.
        *   **Canaries and second opinions**: names the trusted resolver confirmed (the apex, then each confirmed hit) become canaries. A member is asked a canary every 25 lookups (before each lookup while it is untrusted); one that has not answered its last canary correctly has its NXDOMAIN answers checked by a second member.
        *   **Flagging**: every contradiction counts against the member; three take it out of rotation for the rest of the run. If every member is flagged, the trusted resolver answers alone.

        Per-member counts appear in the run-quality report.
    *   **Lookups**: `dns.ResolveTypes` performs one lookup per requested record type (A and AAAA via `LookupIP`, CNAME via `LookupCNAME`; default `dns.DefaultTypes`, A and AAAA) and returns typed `dns.Record{Type, Value}` results, the time spent, and the most severe error. Each type gets its own timeout, so a slow A answer cannot starve AAAA or CNAME. Names are queried as absolute (trailing dot) so resolv.conf search suffixes never multiply queries. `dns.ResolveWithLog` adds verbose per-lookup lines through a `dns.Logf` callback (the package never writes to stderr itself; `dns.StderrLogf` is the unsynchronized fallback). `dns.ResolveDomain` is a convenience wrapper that reports only whether A/AAAA records exist.
    *   **Retries and classification**: `dns.ResolveDomainWithRetry` calls `ResolveWithLog` up to the `-attempts` count with a short linear backoff, and returns the records plus a `dns.Outcome`: `OutcomeFound`, `OutcomeNXDomain`, `OutcomeTimeout`, `OutcomeRefused`, `OutcomeOther`, or `OutcomeCanceled`. `dns.Classify` maps a resolver error onto an outcome. NXDOMAIN (including NODATA, a name with no records of the requested types) is definitive and not retried; any infrastructure failure on one type outranks a not-found answer on another, so a SERVFAIL is never mistaken for NXDOMAIN.
    *   **Rate limiting**: `dns.RateLimiter` hands out evenly spaced reservations; `dns.WithLimiter` attaches it to a context. `ResolveTypes` reserves one slot per query a lookup is expected to send (one for A or AAAA, three for CNAME, since Go's `LookupCNAME` sends A, AAAA and CNAME queries) before that lookup's timeout starts. A per-lookup `wireBudget` travels on the context into the `Dial` hook: Go's resolver dials once per query, so any dial beyond the reserved slots (Go's own internal retries) waits for another slot. `-rate` therefore bounds queries on the wire, including retries, wildcard probes and the preflight. The same hook notices REFUSED responses, which Go reports only as "server misbehaving", and names the server actually dialed in errors.
    *   **Wildcard detection**: probes resolve random 32-character hex labels (`dns.RandomLabel`) under a domain for the scan's record types, each with the scan's `-attempts`, on the trusted resolver. If any probe resolves, the domain is a wildcard and the union of the answers is its fingerprint.
        *   `dns.FingerprintWildcard` checks the scan root, whose fingerprint filters every result. It starts with five probes. If the fingerprint grew after the first probe (a wildcard served from a rotating CDN or load-balancer pool), it keeps probing until the fingerprint has not grown for max(8, 4 x its size) consecutive probes, up to 128 probes in all, so the whole address pool is learned rather than the few addresses the first probes happened to see.
        *   `dns.CheckWildcard` is the cheap variant used for each new parent in a recursive scan: two probes, no saturation.
        *   **Inconclusive**: a check is conclusive only when every probe ended found or NXDOMAIN/NODATA. Any timeout, refusal or other failure ends the check with an error wrapping `dns.ErrWildcardInconclusive`, which callers must never treat as "no wildcard": the scan stops unless `-force` is set, and then it runs without a fingerprint to filter with.
        *   The worker's near-miss revalidation (see 2.4) keeps adding to the fingerprint during the scan when a rotating pool shows addresses the probes missed.
    *   **Simulation**: `dns.SimulateResolve` derives a deterministic result from the name and the `-seed`, with `-hit-rate` percent of names resolving to synthetic records, so the same seed reproduces the same scan. No packets are sent.
*   **Interactions**: Workers call `dns.ResolveDomainWithRetry` (or `dns.SimulateResolve` under `-simulate`) and use the returned records and outcome; the records become an `EventResult`, the outcome feeds the `Stats` counters and the reliability guard.

### 2.4. Concurrency Management (`internal/scan`)

*   **Purpose**: To efficiently perform DNS lookups for a large number of potential subdomains, `subenum` employs a worker pool pattern. This allows multiple DNS queries to be in flight concurrently, significantly speeding up the enumeration process compared to sequential lookups.
*   **Implementation**: The scan engine lives in `internal/scan/runner.go` as `scan.Run`, which takes a context, a `scan.Config`, and an events channel. Both the CLI (`scanTarget` in `main.go`) and the TUI call it.
    *   **`scan.Options` / `scan.Config`**: `Options` holds the user-facing settings (timeout in milliseconds, attempts, rate, and so on). Its `Validate` method checks ranges and the resolver address, and its `Config` method builds the `scan.Config` the engine runs on. The CLI and the TUI each fill in an `Options`, so they cannot drift apart in what they accept.
    *   **`scan.Event` / `scan.EventKind`**: Typed events emitted on the channel: `EventResult` (domain and records), `EventProgress`, `EventNotice`, `EventError`, and `EventDone`. An `EventNotice` carries a `scan.NoticeKind` (`NoticeWildcard`, `NoticeCap`, `NoticeCeiling`, `NoticeSkip`) so consumers can style or filter notices without parsing the message. `EventDone` carries a `scan.Stats` snapshot with per-outcome counters (found, nxdomain, timeout, refused, other, wildcard-filtered).
    *   **Preflight and wildcard check**: Before any candidate is dispatched, `scan.Run` resolves the apex (with retries) and runs `dns.FingerprintWildcard`; see the Data Flow section.
    *   **Dispatcher and lazy candidate generation**: A dispatcher goroutine owns the internal `jobs` channel, a queue of *expansions* (a parent name plus a cursor into `Config.Entries`), a visited set, and a pending-work counter. Candidate names are built only as they are dispatched, so a found parent costs one queue entry rather than one per wordlist entry, and the queue is compacted as it is consumed. `-max-queries` stops admission once the cap is reached; the remaining candidates are counted, never built, and reported in a `NoticeCap` notice.
    *   **Recursion ceiling**: When `-recursive` is set, `scan.RecursionCeiling` computes the theoretical job count (`sum n^d`). Above 1e7 the scan refuses to start unless `-max-queries` or `-force` is set; otherwise a `NoticeCeiling` warning is emitted.
    *   **Worker goroutines**: The pool size is `Config.Concurrency`, capped at the most jobs the scan can produce. Each worker reads a job (which already holds the full domain), waits on the rate limiter if the scan is simulated, resolves it, classifies the outcome, and checks the result against the wildcard fingerprint.
    *   **Near-miss revalidation**: A result whose records are all in the fingerprint is a wildcard answer and is counted as wildcard-filtered. A result that shares *some* records with it is a near miss, typical of a rotating wildcard pool: two fresh random labels under the same parent are probed, their answers join the fingerprint, and the result is checked again. Results sharing nothing with the fingerprint cost no extra queries.
    *   **Reliability guard**: Once 200 jobs have completed, if more than 20% failed as timeout/refused/other, the scan emits `EventError` and cancels unless `-no-abort` is set (then it only warns). Lookups cut short by cancellation are not counted, so an interrupt cannot trip the guard.
    *   **Recursive enumeration** (optional): when `Config.Recursive` is set and a job below the depth cap resolves, the worker first checks the new parent with `dns.CheckWildcard` (cached per parent; inconclusive results are not cached). A wildcard or inconclusive parent is not expanded and a `NoticeSkip` notice is emitted. Otherwise the parent is handed to the dispatcher, whose visited set deduplicates the children (loop and duplicate protection); the progress total grows as new work is admitted.
    *   **Progress ticker**: A separate goroutine emits `EventProgress` once per second. The total is read atomically since recursion can expand it mid-scan.
    *   **Rate limiter** (optional): one `dns.RateLimiter` paces the whole scan. Live scans attach it to the context with `dns.WithLimiter`, so every wire query takes a slot (see 2.3). Simulated scans have no wire traffic and take one slot per job. `0` means unlimited.
    *   **Completion**: a `sync.WaitGroup` waits for all workers (after the dispatcher closes `jobs`), then the progress ticker is stopped and `EventDone` is emitted.
*   **Interactions**: `scan.Run` is the single entry point for scanning used by both the CLI output pipeline and the Bubble Tea TUI. It decouples the scan engine from any specific display layer.

### 2.5. Output Formatting (`internal/output`)

*   **Purpose**: Thread-safe output that keeps stdout pipe-clean. Resolved subdomains go to stdout; everything else (progress, verbose diagnostics, notices, errors) goes to stderr.
*   **Implementation**:
    *   `output.Writer` with mutex-protected methods, created with `output.New` (stdout plus an optional file) or `output.NewFile` (file only; used by the TUI so the alt-screen viewport keeps the terminal):
        *   `Result` - in `text` format prints `Found: <domain>` on a terminal, or the bare name when stdout is piped (`SetPlain`), and the bare name to the output file; `-show-records` (`SetShowRecords`) appends `TYPE=value` pairs. In `json` format results are buffered and written as a single array by `Finish`; `jsonl` streams one object per line; `csv` streams `subdomain,type,value` rows with a header. The format is selected with `-format text|json|jsonl|csv` (`output.ParseFormat`, default `text`).
        *   `Progress` / `ProgressDone` - a carriage-return progress line on stderr, or whole lines when `SetProgressLines` is on.
        *   `Info` / `Error` - informational and error lines on stderr, cleared around the progress line.
        *   `Finish` - writes the buffered JSON array, flushes CSV, and returns the first error writing the output file.
    *   **Simulated output marking**: under `-simulate` every result is marked so invented names never pass for real recon output: text stdout prints `Found (SIMULATED): ...`, a text results file starts with a `# SIMULATED` header naming the seed (`SetSeed`), JSON and JSONL objects carry `"simulated": true` (`output.Result.Simulated`), and CSV gets a `simulated` column.
    *   **Atomic results file**: `output.CreateFile` returns an `output.File` that writes to a temporary file next to the target. `Close(true)` renames it over the target; `Close(false)`, or a failed flush or close, discards it. The CLI commits only if at least one scan finished, so a run that fails before scanning (preflight, wildcard abort, Ctrl+C) leaves an existing results file unchanged. Targets that are not regular files (such as `/dev/stdout`) are written directly.
    *   **Verbose Output** (`-v`): configuration summary, per-lookup resolution lines (through `Info`, serialized with the progress line), and final statistics.
    *   **Progress Reporting** (`-progress`, default on): drawn on stderr only when stderr is a terminal, unless `-progress` was given explicitly (then printed as whole lines).
*   **Interactions**: All CLI output goes through the `Writer`. Since results are the only thing on stdout, and text results are bare names when piped, `subenum ... | sort -u` works without `-progress=false` or any post-processing.

### 2.6. Progress Monitoring

*   **Purpose**: This component tracks the progress of the subdomain enumeration process and provides real-time feedback to the user via stderr.
*   **Implementation**:
    *   **Total Count**: Starts at the number of wordlist entries for the target. The dispatcher republishes it as recursive expansions are admitted, capped at `-max-queries`.
    *   **Counters**: `scan.Run` keeps atomic processed and found counts plus per-outcome counters, which are snapshotted into `scan.Stats` for `EventDone`.
    *   **Progress Display**: The ticker goroutine in `scan.Run` emits `EventProgress` (processed, total, found) every second; the CLI turns it into `Writer.Progress` on stderr and the TUI into its progress bar.
*   **Interactions**: The counters are updated by the worker goroutines with atomic operations, so they are safe to read from the ticker. Writing to stderr keeps stdout pipe-clean.

### 2.7. Session Persistence (`internal/tui/config.go`)

*   **Purpose**: Remember the last-used TUI form values across sessions so users don't have to re-type domain, wordlist path, and scan parameters every time.
*   **Implementation**:
    *   `savedConfig` struct mirrors the form values with JSON tags.
    *   `configPath()` - returns `os.UserConfigDir()/subenum/last.json` (e.g. `~/.config/subenum/last.json` on Linux, `%AppData%\subenum\last.json` on Windows).
    *   `saveConfig` - marshals the form values to JSON, writes them to a temporary file in the same directory, and renames it into place, so a second instance reading at the same moment never sees half-written JSON. It is called when a scan starts; errors are discarded so a write failure never blocks the scan.
    *   `loadSavedConfig` - reads and unmarshals the file. It reports `false` if the file doesn't exist or is unreadable, causing `newFormModel` to fall back to hardcoded defaults.
*   **Interactions**: `tui.New()` calls `loadSavedConfig()` on startup and passes the result to `newFormModel`. The `r` keybind (new scan) also calls `loadSavedConfig()` so the form is pre-filled with the values from the scan that just completed. The form validates through `scan.Options.Validate` and normalizes the domain with `validate.NormalizeDomain`, exactly like the CLI.

## 3. Data Flow

The flow of data through the `subenum` application can be summarized as follows:

1.  **Input**: The user provides command-line arguments: the target domain or a `-dL` domain list, the wordlist (`-w`, `-` for stdin), concurrency (`-t`), timeout (`-timeout`), DNS server (`-dns-server`), attempts (`-attempts`), output options (`-o`, `-format`, `-show-records`), and scan tuning (`-rate`, `-type`, `-recursive`, `-depth`, `-max-queries`, `-no-abort`, `-force`), plus `-v`, `-progress`, and `-simulate` (`-hit-rate`, `-seed`). The TUI (`-tui`) gathers the equivalent values from its form instead.
2.  **Configuration**: These arguments are parsed and validated by the **Argument Parsing** component; the targets are normalized and deduplicated. The wordlist is read once.
3.  **Per-target scans**: Each target is an independent scan with its own wordlist build, preflight, wildcard check, `-max-queries` budget, rate limiter, and reliability guard. All targets share one `Writer`, so `-format json` is still a single array and CSV has a single header. With several targets, each is announced on stderr and a status table (`ok`, `failed`, `skipped`, `not run`) is printed at the end.
4.  **Preflight**: Inside `scan.Run` the apex is resolved once (with retries, skipped in simulation mode). Any outcome other than Found or NXDOMAIN emits `EventError` naming the resolver and returns.
5.  **Wildcard detection**: `dns.FingerprintWildcard` probes random labels under the target (skipped in simulation mode). If the check is inconclusive the scan stops, unless `-force` is set, in which case it scans without filtering and says so in a `NoticeWildcard` notice. If a wildcard is detected, a `NoticeWildcard` notice is emitted and the scan stops unless `-force` is set; with `-force`, later results matching the fingerprint are filtered.
6.  **Dispatch**: The dispatcher generates `prefix.target` jobs lazily from the root expansion, deduplicated through a visited set, and feeds the internal `jobs` channel. It does not close `jobs` until no candidates remain and the pending counter drains to zero, or the context is cancelled.
7.  **Resolution**: Worker goroutines read jobs and call `dns.ResolveDomainWithRetry` (or `dns.SimulateResolve`) for the requested record types; every wire query waits on the rate limiter.
8.  **Result Emission**: A found result that is not a wildcard answer increments the found counter and is emitted as an `EventResult` with its typed records. Every completed lookup, success or failure, increments the matching `Stats` counter. The CLI `Writer` routes results to stdout and any `-o` file in the selected `-format`; the TUI renders them in its viewport. After `EventDone` the CLI prints the per-outcome breakdown to stderr and the TUI summary line shows the same counters.
9.  **Recursive Expansion** (optional): when `-recursive` is set and a resolved, non-wildcard job is below the `-depth` cap, the worker hands it back to the dispatcher over the `enqueue` channel, which adds an expansion for its children and grows the progress total.
10. **Progress Tracking**: Workers update atomic counters; the ticker goroutine emits `EventProgress` once per second.
11. **Termination**: Each worker signals completion of a job over the `completed` channel. When no work remains the dispatcher closes `jobs`, the workers exit, and `scan.Run` waits on the `sync.WaitGroup`, stops the progress ticker, emits `EventDone`, and closes the events channel. On `SIGINT`/`SIGTERM` the context is cancelled, the dispatcher closes `jobs` early, and the same drain-and-finish path runs with partial counts.
12. **Finalization**: If at least one scan finished, the CLI calls `Writer.Finish` and commits the `-o` file, then exits with the code described in 4.5.

Visually, this can be seen as:

`User Input -> Argument Parser -> scan.Options -> scan.Config -> scan.Run() [Preflight -> Wildcard fingerprint -> Dispatcher -> jobs -> Worker Pool -> DNS Resolver] -> Event Channel -> Output (if resolved)`

## 4. Error Handling Strategy

`subenum` handles different types of errors at various stages of its operation:

### 4.1. User Input Errors

*   **Missing Required Arguments**: When `-w` or a target (domain or `-dL`) is missing, the tool says what is missing, prints the usage message and flag list, and exits with status 2.
*   **Validation** (status 2 on failure): the tool validates:
    *   Concurrency, timeout, attempts and depth must be at least 1; `-rate` and `-max-queries` must be 0 (unlimited) or positive. These checks live in `scan.Options.Validate`.
    *   The DNS server must be a valid `ip:port` with an IP host and a port in 1-65535 (`validate.DNSServer`; not checked in simulation mode).
    *   The target domain must conform to DNS naming rules after normalization (`validate.NormalizeDomain`, `validate.Domain`). In a `-dL` list, invalid domains are skipped with a message instead.
    *   Hit rate (simulation mode) must be 1-100.
    *   `-format` and `-type` must name supported values; `-attempts` and `-retries` cannot both be set.
    *   Only one positional domain is accepted, not together with `-dL`, and `-w` and `-dL` cannot both read stdin.

### 4.2. File Operation Errors

*   **Wordlist or domain list cannot be read**: the tool prints an error (`reading wordlist file: ...` or `reading domain list: ...`) and exits with status 1. A wordlist with no valid entries, or a domain list with no valid domains, is also status 1.
*   **Output file**: if the `-o` file cannot be created the tool exits with status 1 before scanning. A failed write, flush, close or rename at the end is reported and turns a successful exit into status 1; the partial temporary file is discarded and an existing results file is left unchanged.

### 4.3. DNS Resolution Errors

*   **Lookup Failure**: When a DNS lookup fails, the error is classified (`NXDomain`, `Timeout`, `Refused`, `Other`, `Canceled`) and counted. NXDOMAIN is a definitive negative and is not treated as an infrastructure failure; this bucket also covers NODATA (the name exists but has no records of the requested types, such as `-type CNAME` on a name with only A records). Lookups cut short by cancellation (`Canceled`) are not counted at all, so an interrupt cannot inflate the failure rate. Timeouts, refusals, and other errors feed the reliability guard. The CLI always prints the per-outcome breakdown after `EventDone`.
*   **Timeout Handling**: The user-specified timeout (`-timeout` flag) limits each per-type lookup, starting only after its rate-limit slots are granted, so queueing behind `-rate` never turns into a timeout. A lookup that exceeds it is classified as a timeout and retried if attempts remain.
*   **Resolver failures before scanning**: a failed preflight or an inconclusive wildcard check (without `-force`) emits `EventError` and ends the scan without `EventDone`; the target counts as failed.

### 4.4. Concurrency-Related Issues

*   **Channel Operations**: The scan engine uses three internal channels (`jobs`, `enqueue`, `completed`) plus the outbound `events` channel. To avoid the classic send-on-closed and double-close panics, only the dispatcher closes `jobs`, and it does so exactly once (when no work remains or the context is cancelled); `enqueue` and `completed` are never closed. The `events` channel is closed by `scan.Run` only after the worker `WaitGroup` returns and the progress ticker has confirmed its exit, so no in-flight send can race the close. Callers must drain `events` until it is closed: the result and done sends are not individually guarded against a consumer that stops reading early, so a consumer that wants to stop on cancellation should keep draining until close rather than abandoning the channel.
*   **Worker Goroutine Errors**: Each worker goroutine processes DNS lookups independently. If an error occurs within a worker (outside of the expected DNS resolution failures), it can cause the entire goroutine to terminate. The current implementation doesn't have specific handling for such scenarios.

### 4.5. Graceful Shutdown and Exit Codes

The tool listens for `SIGINT` and `SIGTERM`. On the first signal it cancels the work context, drains in-flight workers, finalizes the output written so far, and exits with the shell convention 128+signum; a second Ctrl+C force-quits a run stuck draining. Exit codes (also listed in `-h`):

*   `0` - success.
*   `1` - a scan, the wordlist, the domain list or the output file failed.
*   `2` - invalid flags or arguments.
*   `3` - `-dL`: some targets failed while others completed.
*   `4` - `-diff`: names were added or removed (or, with `-diff-records`, changed) since the previous run.
*   `130` - interrupted (SIGINT, Ctrl+C); partial results are kept.
*   `143` - terminated (SIGTERM); partial results are kept.

With `-dL`, a reliability-guard abort means the resolver is overloaded, so the remaining targets are skipped (and counted as failed) rather than sent to it too; `-no-abort` keeps going.

### 4.6. Output File Support

When the `-o` flag is provided, results are written to the specified file in the selected `-format` in addition to stdout. The file is replaced atomically (see 2.5), and a mutex in the `Writer` protects concurrent writes to both stdout and the file.

### 4.7. Retry Mechanism

The `-attempts` flag (default: 1) controls the total number of DNS resolution attempts per subdomain. A value of 1 means no retries. A short linear backoff delay is applied between attempts to handle transient DNS failures (timeout, refused, other). NXDOMAIN is a definitive negative and is not retried. The same attempt count applies to the preflight and to wildcard probes. The deprecated `-retries` flag is still accepted as an alias but prints a warning to stderr.

## 5. Other Subsystems

Each subsystem below is small and documented in its source; this section says what it does and where to look.

| Subsystem | Where | Summary |
| --- | --- | --- |
| Run-quality verdict | `internal/scan/verdict.go`, `internal/report`, `main_summary.go` | Grades each finished scan, and the run (the worst target), as `complete`, `degraded` or `unreliable` with a reason (5.1). |
| Scope (`-exclude`) | `internal/scan/scope.go` | Out-of-scope names are never queried or expanded (5.2). |
| Resume state (`-resume`, `-state`) | `main_resume.go` | An interrupted run saves its state; `-resume` replays it and continues (5.3). |
| Permutation pass (`-permute`, `-seeds`) | `internal/permute`, `main_permute.go` | A second scan over variations of the names found (5.4). |
| CT seeding (`-ct`) | `internal/ct`, `main_ct.go` | Adds names from Certificate Transparency logs as candidates (5.5). |
| Lab mode (`-simulate-zone`) | `internal/labzone`, `internal/dnsserver`, `main_lab.go` | Serves a scenario file on a loopback DNS server (5.6). |
| SARIF (`-sarif`) | `internal/output/sarif.go`, `internal/dns/takeover.go` | Writes takeover candidates as SARIF 2.1.0 (5.7). |
| Config and environment defaults | `main_config.go` | Flag > environment > config file > built-in default (5.8). |
| Go API | `pkg/subenum` | The engine as a library (5.9). |

### 5.1. Run-Quality Verdict

`scan.Stats.Verdict` grades a scan that reached `EventDone`: `unreliable` when the reliability guard aborted it or more than 20% of lookups failed; `degraded` when it was interrupted, at least 1% of lookups failed, or `-max-queries` or `-max-duration` left candidates untested; otherwise `complete`. The reason names settings as `{tokens}` (`internal/scan/settings.go`) that each front end renders in its own terms (`-max-queries` in the CLI). `internal/report` builds the run summary for the CLI and the TUI; the CLI writes it as the final line of `jsonl` output and to the `-stats` file, including per-resolver counts when `-r` is used.

### 5.2. Scope and Exclusions

`-exclude` takes exact names and `*.parent` patterns. An exact pattern excludes that name; `*.parent` excludes every name below `parent` but not `parent` itself. Patterns are normalized like targets (lowercase, no trailing dot, punycode) and checked with `scan.ValidateExcludes`. The dispatcher never queries or recursively expands an excluded name, and counts it as excluded in the report.

### 5.3. Resume State

On `SIGINT`/`SIGTERM` the CLI writes a state file (`-state`, default `subenum-resume.json`) holding the original command line, the effective settings (including those from the environment and config file), a sha256 of each input file and of each target's normalized wordlist, and per-target progress: whether it finished, how many wordlist entries were settled, its stats, the names found so far, the `-permute` pass's progress and the `-ct` names fetched. `subenum -resume <file>` replays the command line, refuses to continue if an input changed, re-emits the saved results and continues each target where it stopped. Runs that read stdin cannot be resumed.

### 5.4. Permutation Pass

With `-permute` (or `-seeds`, which implies it), each target that finished gets a second scan. `permute.Generate` permutes the leftmost label of every name found by the main pass (and of names in the `-seeds` file): `api` suggests `api-dev`, `dev-api`, `dev.api`, `api2` and so on. Candidates already in the wordlist or among the seeds are skipped, so nothing is queried twice. The pass is a full, guarded scan with its own preflight, wildcard filtering, `-rate`, `-max-queries` and `-exclude`. It is skipped after an interrupt or a reliability-guard abort, and its hits are marked as permutation results.

### 5.5. Certificate Transparency Seeding

With `-ct`, `ct.Client.Names` makes one HTTPS request per target to crt.sh (no API key) and returns the names its certificates cover, relative to the target. `withCTEntries` appends those not already in the wordlist after the wordlist entries, so wordlist resume positions stay put. They are only candidates and are resolved like any other; those that resolve also seed `-permute`. A failed lookup is a warning, not a failed scan. A resumed run reuses the saved CT names so its candidate list is the same.

### 5.6. Lab Mode

`-simulate-zone <file>` loads a scenario with `labzone.Load` (exact names, records, `*.name` wildcards, and `TIMEOUT`, `SERVFAIL`, `REFUSED` or `NXDOMAIN` entries, plus `$DELAY` and `$REFUSE-ABOVE` directives), serves it with `dnsserver.Listen` on a loopback port and points `-dns-server` at it (`startLabZone`). Unlike `-simulate`, the scan then runs the real resolver, wildcard detection, `-rate` pacing and reliability guard, and no traffic leaves the machine. The same `internal/dnsserver` backs the hermetic tests through `internal/dnstest`.

### 5.7. SARIF Output

`-sarif <file>` writes the run's takeover candidates (results whose CNAME `dns.TakeoverHint` marked as dangling or pointing at a takeover-prone provider) as a SARIF 2.1.0 log with `output.WriteSARIF`, atomically, for GitHub code scanning. It needs `CNAME` in `-type`. A run with no candidates writes a valid document with no results.

### 5.8. Configuration Precedence

`main_config.go` fills flag defaults from a JSON config file (`$SUBENUM_CONFIG`, else `<user config dir>/subenum/config.json`) and from `SUBENUM_*` environment variables named after the flag (`-dns-server` is `SUBENUM_DNS_SERVER`). Precedence, highest first: command-line flag > environment > config file > built-in default. Mode and action flags (`-tui`, `-version`, `-print-config`, `-resume`, `-h`) are never taken from defaults. `-print-config` prints every setting's effective value and its source. An invalid config value is a usage error, except under `-version`, `-print-config` and `-tui`, which only warn so the value can be found and fixed. The TUI pre-fills its form from the same environment and config values.

### 5.9. Go API (`pkg/subenum`)

`pkg/subenum` exposes the same engine to other Go programs. `subenum.Scan` runs a scan to completion and returns its results and stats (with the partial results when it fails); `subenum.Run` streams results, notices and progress as events; `subenum.DefaultWords` returns the bundled wordlist. Its `Simulate` option produces synthetic results without sending queries, which is what examples and tests should use. The package follows semantic versioning from v1.0.0; until then it may change between minor releases.
