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

```
main.go                        - CLI entry point: flag parsing, -dL target loop, exit codes, -tui dispatch
internal/scan/options.go       - Options: user-facing settings shared by CLI and TUI (Validate, Config)
internal/scan/runner.go        - Scan engine: Config, Event/EventKind/NoticeKind, Stats, Run
internal/dns/resolver.go       - NewResolver, ResolveTypes, ResolveDomainWithRetry, Classify,
                                 CheckWildcard, FingerprintWildcard, ParseTypes
internal/dns/ratelimit.go      - RateLimiter, WithLimiter (per-wire-query pacing)
internal/dns/simulate.go       - SimulateResolve (seeded synthetic DNS)
internal/output/writer.go      - Thread-safe Writer (results to stdout, diagnostics to stderr)
internal/output/file.go        - File: atomically replaced -o results file
internal/validate/validate.go  - DNSServer, Domain, NormalizeDomain, DefaultDNSServer
internal/validate/punycode.go  - IDN to punycode (A-label) conversion
internal/wordlist/reader.go    - ReadLines, Normalize, Build, LoadWordlist
internal/tui/model.go          - Root Bubble Tea model (form -> scan state machine)
internal/tui/form.go           - Config form screen (textinput fields + toggles)
internal/tui/scan_view.go      - Live results screen (viewport + progress bar)
internal/tui/logo.go           - Styled wordmark
internal/tui/config.go         - Session persistence (load/save <user config dir>/subenum/last.json)
tools/wordlist-gen.go          - Standalone wordlist generator
```

## 2. Key Components / Modules

### 2.1. Argument Parsing (`main.go`, `internal/validate`)

*   **Purpose**: This component is responsible for processing the command-line arguments provided by the user when `subenum` is executed. It extracts the target domain (or a `-dL` domain list), the wordlist path, and every scan, output, and tuning option.
*   **Implementation**: Uses a `flag.FlagSet` built by `parseFlags`, which binds every flag into a `cliFlags` struct. The standard `flag` package stops at the first non-flag argument, so `parseInterspersed` re-parses around each positional; flags written after the domain are honored, and everything after a `--` terminator is positional. `run()` then:
    *   handles `-tui` (launches `tui.Start`, ignoring other flags) and `-version` first;
    *   parses `-format` (`output.ParseFormat`), `-type` (`dns.ParseTypes`), and merges `-attempts` with the deprecated `-retries` (`resolveAttempts`);
    *   calls `validateFlags`, which checks that `-w` and a target are present, that a positional domain and `-dL` are not both given, and that `-w` and `-dL` do not both read stdin. Numeric ranges and the resolver address are checked by `scan.Options.Validate`, the same validator the TUI uses. The positional domain is canonicalized with `validate.NormalizeDomain`.
*   **Domain normalization**: `validate.NormalizeDomain` trims and lowercases the input, strips a URL scheme and path, a `:port`, a leading `*.` and a trailing dot (returning a note for each change), converts IDNs to punycode, and checks the result with `validate.Domain`. `validate.DNSServer` checks the `ip:port` resolver format. Both are shared with the TUI.
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
    *   **Resolver**: `dns.NewResolver` builds a `net.Resolver` with `PreferGo: true` whose `Dial` hook always connects to the configured server. It honors the `network` argument (`udp` or `tcp`), so a truncated UDP response (TC=1) falls back to TCP. `scan.Run` builds one per scan (unless `Config.Resolver` is set) and reuses it for every lookup.
    *   **Lookups**: `dns.ResolveTypes` performs one lookup per requested record type (A and AAAA via `LookupIP`, CNAME via `LookupCNAME`; default `dns.DefaultTypes`, A and AAAA) and returns typed `dns.Record{Type, Value}` results, the time spent, and the most severe error. Each type gets its own timeout, so a slow A answer cannot starve AAAA or CNAME. Names are queried as absolute (trailing dot) so resolv.conf search suffixes never multiply queries. `dns.ResolveWithLog` adds verbose per-lookup lines through a `dns.Logf` callback (the package never writes to stderr itself; `dns.StderrLogf` is the unsynchronized fallback). `dns.ResolveDomain` is a convenience wrapper that reports only whether A/AAAA records exist.
    *   **Retries and classification**: `dns.ResolveDomainWithRetry` calls `ResolveWithLog` up to the `-attempts` count with a short linear backoff, and returns the records plus a `dns.Outcome`: `OutcomeFound`, `OutcomeNXDomain`, `OutcomeTimeout`, `OutcomeRefused`, `OutcomeOther`, or `OutcomeCanceled`. `dns.Classify` maps a resolver error onto an outcome. NXDOMAIN (including NODATA, a name with no records of the requested types) is definitive and not retried; any infrastructure failure on one type outranks a not-found answer on another, so a SERVFAIL is never mistaken for NXDOMAIN.
    *   **Rate limiting**: `dns.RateLimiter` hands out evenly spaced reservations; `dns.WithLimiter` attaches it to a context. `ResolveTypes` reserves one slot per query a lookup is expected to send (one for A or AAAA, three for CNAME, since Go's `LookupCNAME` sends A, AAAA and CNAME queries) before that lookup's timeout starts. A per-lookup `wireBudget` travels on the context into the `Dial` hook: Go's resolver dials once per query, so any dial beyond the reserved slots (Go's own internal retries) waits for another slot. `-rate` therefore bounds queries on the wire, including retries, wildcard probes and the preflight. The same hook notices REFUSED responses, which Go reports only as "server misbehaving", and names the server actually dialed in errors.
    *   **Wildcard detection**: `dns.CheckWildcard` resolves two random labels (`dns.RandomLabel`) under a domain for the scan's record types; if either resolves, the domain is a wildcard and the union of the answers is its fingerprint. `dns.FingerprintWildcard` is the root-domain variant: it starts with five probes and, when their answers differ (a wildcard served from a rotating CDN or load-balancer pool), keeps probing until the fingerprint stops growing, so the whole pool is learned. A check is conclusive only when every probe ended found or NXDOMAIN; otherwise the error wraps `dns.ErrWildcardInconclusive`, which callers must never treat as "no wildcard".
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
*   `130` - interrupted (SIGINT, Ctrl+C); partial results are kept.
*   `143` - terminated (SIGTERM); partial results are kept.

With `-dL`, a reliability-guard abort means the resolver is overloaded, so the remaining targets are skipped (and counted as failed) rather than sent to it too; `-no-abort` keeps going.

### 4.6. Output File Support

When the `-o` flag is provided, results are written to the specified file in the selected `-format` in addition to stdout. The file is replaced atomically (see 2.5), and a mutex in the `Writer` protects concurrent writes to both stdout and the file.

### 4.7. Retry Mechanism

The `-attempts` flag (default: 1) controls the total number of DNS resolution attempts per subdomain. A value of 1 means no retries. A short linear backoff delay is applied between attempts to handle transient DNS failures (timeout, refused, other). NXDOMAIN is a definitive negative and is not retried. The same attempt count applies to the preflight and to wildcard probes. The deprecated `-retries` flag is still accepted as an alias but prints a warning to stderr.
