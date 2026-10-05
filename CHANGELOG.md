# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Subdomain takeover hints: results with a CNAME are marked `dangling` (target is NXDOMAIN), `provider:<name>` (target at a takeover-prone service such as S3, GitHub Pages, Heroku or Azure) or `dangling:<name>`. The marker appears in JSON/JSONL (`takeover_candidate`), as a CSV column when CNAME records are requested, in text with `-show-records`, in the TUI, and as a count in the breakdown and report. DNS-only; no HTTP probing (#71).
- Resolver pool: `-r resolvers.txt` spreads lookups over many resolvers, round-robin over the healthy ones (a resolver failing over half its recent lookups is benched for 30s), with retries sent to a different resolver. Every pool hit is re-validated against `-dns-server`, whose answer is reported, so a lying pool resolver cannot inject results. Per-resolver accounting appears in a stderr table and in the run-quality report, with `pool_hits` / `confirmed` / `unconfirmed` per target. In a hermetic test, 20 rate-limited resolvers ran the same scan 14x faster than one (#69).
- Scope control: `-exclude 'vpn.example.com,*.corp.example.com'` and `-exclude-file` keep out-of-scope names out of a scan. Excluded names are never queried, wildcard-probed or expanded recursively (a found parent whose whole subtree is excluded costs no queries), they are counted as `excluded` in the breakdown and the run-quality report, and a target that is itself out of scope is refused. The TUI has a matching Exclude field (#87).
- Run-quality report: `-stats <file>` writes a schema-versioned JSON summary of a run (outcomes per target, DNS queries actually sent, achieved query rate, wildcard fingerprint, candidates skipped by `-max-queries`) with a `complete` / `degraded` / `unreliable` verdict and its reason. `-format jsonl` ends with the same object as its last line. The README documents the schema and how to gate CI on the verdict (#70).

### Changed
- The minimum Go version is now 1.26 (`go 1.26.0` in go.mod), required by current `golang.org/x/sys` and `golang.org/x/text`; both were bumped and `govulncheck -show verbose` now reports no vulnerable modules. Dependabot also updates indirect modules, and CI lints with errorlint, nilerr, contextcheck, noctx, copyloopvar, usestdlibvars and revive, with errcheck exemptions narrowed to stdout prints (#83).

### Fixed
- A wildcard check whose probes time out or SERVFAIL is no longer read as "no wildcard". Probes are retried up to `-attempts`; if still inconclusive, the scan aborts (scans without filtering under `-force`, with a warning), and in recursive mode the branch is skipped and not cached. Previously a wildcard zone with flaky probes reported every wordlist entry as a hit (#47).
- The dispatcher no longer does quadratic queue copying, so large wordlists scale linearly (simulated 2M entries: 19.4s down to 4.6s). Candidate names are generated lazily from the wordlist instead of being built up front, and a found parent is expanded in the dispatcher instead of pushing every child through a channel. `make bench` runs a 1M-entry benchmark (#49).
- `-o` results files are written to a temporary file beside the target and renamed into place only once a scan finishes (including an interrupted one with partial results), in both the CLI and the TUI. A run that fails before scanning (preflight failure, wildcard abort, recursion refusal, Ctrl+C during preflight) no longer truncates an existing results file (#52).
- Progress no longer corrupts results when stdout and stderr are merged (`2>&1`, `tee`, CI logs). Progress is off by default when stderr is not a terminal, an explicit `-progress` there prints whole lines with no carriage returns, and an active progress line is always ended before a result is printed (#78).
- Simulated results identify themselves wherever they are saved: JSON and JSONL objects carry `"simulated": true`, CSV gets a `simulated` column, `-o` text files start with a `# SIMULATED ... -seed N` comment line, and the CLI ends a simulated run with a stderr reminder. Piped bare names stay unmarked (#53).
- The preflight lookup of the target domain is retried up to `-attempts`, so one dropped packet no longer aborts the scan (#57).
- `-max-queries` now stops memory growth in recursive mode: once the cap is reached, remaining and future candidates are counted as skipped without being built or recorded (#51).
- No default command sends DNS traffic at a domain you did not name. `docker compose up`, `make simulate*` and `examples/demo.sh` run in simulation mode; `make run`, `run-verbose`, `run-custom` and `docker-run` require `DOMAIN=` and stop with a message without it; `demo.sh -l <domain>` opts into a live run. `demo.sh` now uses `set -euo pipefail`, `docker-run` uses `$(CURDIR)` so it works under Windows make, and `.PHONY` lists every target (#81).
- Target domains are normalized the same way in the positional argument, `-dL` and the TUI: trimmed, lowercased, trailing dot dropped, so `Example.COM.` no longer yields `api.Example.COM.`. A pasted URL, path, `:port` or leading `*.` is stripped with a one-line note, IDNs such as `bücher.de` are converted to punycode, underscores are accepted as in wordlist entries, and an email address gets a targeted hint instead of `invalid domain format` (#54).
- TUI: a `-` wordlist is rejected on the form instead of freezing the UI on stdin, the wordlist loads in the background with a "Loading wordlist..." line so large lists no longer block input, a scan that ends with an error (preflight failure, wildcard abort, reliability abort) shows "Failed: <reason>" instead of "Aborted", and the TUI exits 1 when the last scan failed (#55).
- `-rate` now charges every DNS query that reaches the wire. A CNAME lookup costs three slots (Go sends A, AAAA and CNAME queries), and queries Go's resolver retries internally on SERVFAIL, REFUSED or socket errors are charged as they are dialed, so a struggling resolver no longer gets more traffic than `-rate` allows. Responses with RCODE REFUSED are now counted as `refused` instead of `other`, and lookup errors name the configured `-dns-server` instead of the system nameserver (#50).
- Wildcards that answer from a rotating CDN or load-balancer pool are now filtered under `-force`. The root fingerprint starts from five probes instead of two and, when their answers differ, keeps probing until the pool stops growing; results that share only some records with the fingerprint are re-validated with fresh probes under the same parent. In a hermetic 8-address pool test, filtering went from 12 of 50 wildcard answers to all 50, with no real names lost (#48).
- A wordlist line longer than 64 KB no longer aborts the run with `bufio.Scanner: token too long`. Overlong lines are truncated, skipped and counted with the other invalid entries (#56).
- `tools/wordlist-gen` no longer overwrites an existing output file without the new `-f` flag, exits 1 instead of writing an empty file when nothing is generated, rejects `-combine` prefixes that are not valid DNS labels, and drops generated entries subenum would skip (for example combinations over 63 characters). `make wordlist` and `examples/demo.sh` pass `-f` for the files they own (#59).
- CLI polish: `-h` shows the `-attempts` default, a missing `-w` or domain is named before the usage text, `-version` prints before the simulation banner, `-tui` is only honoured as a flag (not as `-o -tui` or after `--`) and warns that other flags are ignored, and the worker pool is capped at the number of jobs the scan can produce, with a warning above `-t 10000` (#58).
- Exit codes are consistent and documented in the README and `-h`: 2 for every usage error (previously 1 for semantic ones such as a missing domain or bad `-format`), 3 when some `-dL` targets failed while others completed, and 143 instead of 130 for SIGTERM, without the Ctrl+C hint. With `-dL`, a reliability abort now skips the remaining targets instead of sending them to the same overloaded resolver (unless `-no-abort`), and a per-target status list is printed at the end (#82).
- The CLI and the TUI now share one `scan.Options` validator and `scan.Config` builder, so they accept the same values and build identical scans. The TUI now shows the simulation seed (so runs can be reproduced) and the number of skipped wordlist entries, skips the resolver check in simulation mode like the CLI, and saves its settings atomically. The default resolver is a single constant. The CLI no longer rejects an unused `-hit-rate` outside simulation mode (#80).
- Release binaries are built with `CGO_ENABLED=0 -trimpath -s -w`, so `subenum-linux-amd64` is statically linked again and CI fails if a Linux asset is not (#46).

## [0.8.0] - 2026-10-04

### Fixed
- Flags written after the domain (`subenum -w wl.txt example.com -t 50`) are now parsed instead of silently ignored. Extra positional arguments are rejected, `-h` exits 0, and unknown flags exit 2 (#29).
- `-type CNAME` no longer counts names that exist without a CNAME as resolver failures (`other`). A successful lookup with no records of the requested types is now a definitive negative (counted under `nxdomain`, not retried), so it cannot trip the reliability guard. Wildcard probes now use the requested record types, so CNAME wildcards are fingerprinted and filtered under `-force` (#28).
- Lookups cut short by Ctrl+C, SIGTERM, or the reliability guard's own cancellation are no longer counted as failures, which previously inflated `other` and could raise a false "likely resolver rate-limiting" abort with exit 1. An interrupted CLI scan now exits 130 after flushing partial results (#42).
- Output-file write failures (disk full, closed handle) now make the CLI exit 1 instead of 0, and the TUI shows an "output file incomplete" error instead of discarding it. `Writer.Finish` returns the first file write error, including CSV writer errors. The output file is created only after the wordlist loads, so a bad `-w` path no longer truncates an existing `-o` target (#30).
- `-rate` now bounds DNS queries on the wire instead of candidate names. Every record type (CNAME counts as two), retry, wildcard probe and the preflight takes a slot, so `-rate 50` with the default `A,AAAA` no longer sends up to 100 qps. A reservation-based `dns.RateLimiter` replaces the ticker, which dropped ticks and under-delivered under load (ROADMAP N1). Time spent waiting for a slot does not count against `-timeout` (#32).
- Each record type now gets its own `-timeout`, so a slow A answer no longer starves the AAAA/CNAME lookups that shared its budget (ROADMAP N3).
- `ResolveTypes` reports the most severe per-type error instead of the last one. An A SERVFAIL or timeout followed by an AAAA NXDOMAIN is now a failure that `-attempts` retries and the reliability guard sees, instead of a silent NXDOMAIN miss (#31).
- Lookups use absolute names (trailing dot), so resolv.conf search suffixes (for example Kubernetes `ndots:5`) no longer multiply the queries sent for every missing name.
- TUI scan view: the viewport height is clamped to at least one row, so terminals shorter than the layout no longer produce a negative height (#37, ROADMAP N6). The layout reserve also accounts for the hint margin, which previously overflowed the screen by one line.
- TUI scan view: wildcard and error notices are capped at the latest three (with a "+N earlier notices" line) and the viewport shrinks to fit them, so recursive scans no longer push the progress bar and status off-screen. Ctrl+C on a finished scan now quits instead of relabelling it "Aborted". The results buffer is capped at 10,000 lines and re-rendered on progress ticks once past 200 results, so large scans no longer slow the UI and back-pressure the workers. `~/` paths in the wordlist and output fields are expanded (#43).
- `-v` lines no longer splice into the progress line. The `dns` package no longer writes to stderr; lookups log through `scan.Config.Logf` (the CLI passes `output.Writer.Info`), and `Info`/`Error` now take the writer mutex and blank the in-place progress line before printing (#36, ROADMAP N5).
- `tools/wordlist-gen` output is deterministic: `-combine` no longer iterates a Go map, so the same flags give a byte-identical file. Write errors go to stderr and exit non-zero instead of being swallowed, suffixes such as `.co.uk` are stripped correctly, a prefix is no longer combined with itself, per-entry logging moved behind `-v`, and the generator has unit tests (#45).
- The reliability-guard message printed as `aborting scan: 50%!o(MISSING)f 200 queries failed`: scan event messages were passed to `Info`/`Error` as format strings. They are now printed verbatim (present since 0.7.0).
- Ctrl+C during the preflight lookup or wildcard probes no longer reports a misleading "resolver failed preflight" or "wildcard detection failed" error. A second Ctrl+C now force-quits a run that is stuck draining.
- `-o --` (a flag whose value is `--`) is no longer mistaken for the `--` terminator.
- On a terminal, results no longer start on the same line as the progress indicator, and a UTF-8 byte order mark at the start of a wordlist or `-dL` file no longer invalidates its first entry.

### Added
- `-format jsonl` streams one JSON object per resolved subdomain, so structured output can be piped live (#34).
- `-show-records` appends `TYPE=value` record pairs to `text` output on stdout and in the `-o` file (#34, ROADMAP N2).
- TUI form gains *Max Names* (`-max-queries`) and *No Abort* (`-no-abort`), both persisted in `last.json`. A recursive TUI scan above the 1e7 ceiling can now be started with a cap instead of enabling *Force*, which also disables the wildcard abort (#35).
- `-seed <n>` makes simulation mode reproducible: each outcome, record and reported timing is derived from the seed and the name, so the same seed gives the same results. Without `-seed` a random seed is chosen and printed in the simulation banner (#44).
- Tagged releases publish a multi-arch (`linux/amd64`, `linux/arm64`) image to `ghcr.io/tmhsdigital/subenum` with build provenance, tagged `X.Y.Z`, `X.Y`, and `latest` (non-prereleases only). The Dockerfile now cross-compiles in a build-platform builder stage, so no QEMU emulation is needed (#40).
- `-dL <file>` scans every apex domain in a file (one per line, `#` comments allowed, `-` for stdin) in one process. Each domain is an independent scan with its own preflight, wildcard check, `-max-queries` budget and reliability guard; results share one output, so `-format json` stays a single array. A failing domain (for example a wildcard without `-force`) sets a non-zero exit code but does not stop the others. `-w -` reads the wordlist from stdin (#41, ROADMAP N4).

### Changed
- When stdout is not a terminal, `text` results are printed as bare subdomain names (no `Found:` prefix), so `subenum ... | sort -u` or `| httpx` works without `cut`. Terminal output is unchanged (#34).
- Wordlists are normalized on load: blank lines and `#` comments are ignored, entries are lowercased before deduplication (so `WWW` and `www` are one query), and entries that are not valid DNS labels (whitespace, `*`, empty or over-long labels) or whose full name would exceed 253 characters are skipped and reported on stderr. Underscore labels such as `_dmarc` are kept. A wordlist with no valid entries is an error (#33).
- `-max-queries` help text and docs now say what it counts: candidate names (jobs), not wire queries.
- Release binaries and the Docker image are built with the latest stable Go toolchain (Docker builder `golang:1.27.1-alpine`, digest-pinned) instead of Go 1.24.2. `go.mod` still declares 1.24.2 as the minimum, and CI now tests both the minimum and the latest stable toolchain. CI runs `govulncheck` on every push and PR, and Dependabot tracks the Dockerfile base images. Release jobs build without a shared cache (#38).
- `-version` no longer relies on a hand-maintained `0.7.0` fallback. Without ldflags it reports the module version recorded by `go install` (for example `v0.7.0`), or `dev` for local builds; the Makefile and Dockerfile fallbacks are `dev` too. README and the landing page document `go install github.com/TMHSDigital/subenum@latest` and add a "Why subenum" section (#39).
- Simulation mode applies `-hit-rate` uniformly. Previously 12 common prefixes (`www`, `api`, `dev`, ...) always resolved about 90% of the time, so `-hit-rate 1` still produced many hits and recursive simulate scans grew much faster than the rate suggested (#44).

### Removed
- Removed `examples/multi_domain_scan.sh`, which was bash-only; use `-dL` (#41).

## [0.7.0] - 2026-09-16

### Added
- Scan outcome accounting: each query is classified as found, nxdomain, timeout, refused, or other. The breakdown is printed after every scan (stderr) and carried on `EventDone.Stats` for the TUI summary line.
- Reliability guard: once 200 queries have completed, if more than 20% failed as timeout/refused/other the scan emits an error naming the failure rate and likely resolver rate-limiting at the configured `-t` and `-rate`, then aborts. `-no-abort` keeps the warning but continues the scan.
- TUI record-type selection (`-type` parity): a Record Types form field, persisted to the session config and wired into the scan.
- TUI recursive enumeration (`-recursive`/`-depth` parity): a Recursive toggle with a Depth field gated on it, persisted across sessions.
- TUI rate limiting (`-rate` parity): a queries-per-second form field, persisted across sessions.
- TUI output file support (`-o`/`-format` parity): results can be written to a file as `text`, `json`, or `csv`. The format applies only to the file; the live viewport stays human-readable. Backed by a new file-only `output.NewFile` writer so structured output never collides with the alt-screen.
- Release provenance attestations (`actions/attest-build-provenance`) on tagged builds.

### Changed
- `dns.ResolveDomainWithRetry` returns `([]Record, Outcome)` instead of `([]Record, bool)`, so callers can distinguish NXDOMAIN from infrastructure failure.
- `ResolveDomainWithRetry` no longer retries NXDOMAIN. Timeouts, refusals, and unknown errors still retry up to `-attempts`.
- The resolver Dial hook honors `network`, so truncated UDP answers fall back to TCP. `scan.Run` builds one `*net.Resolver` and reuses it for every lookup.
- Wildcard detection keeps a fingerprint of probe answers. Matching results are dropped (`wildcardFiltered`) even with `-force`. Recursive mode probes each new parent and skips expanding wildcard branches.
- `-max-queries` caps admitted work. Recursive scans warn about the theoretical ceiling and refuse to start above 1e7 jobs unless `-max-queries` or `-force` is set. The dispatcher queue uses a head index with periodic compaction. Unreachable resolvers fail a preflight lookup before wildcard probes.
- CLI `EventError` handling now drains the event channel so a reliability abort still delivers `EventDone` with partial stats. Wildcard-without-`-force` still skips structured `Finish`.
- TUI form now validates domain syntax and DNS server `ip:port` format up front, matching the CLI. The validators were extracted into a shared `internal/validate` package used by both entry points (previously the form only checked for non-empty values).
- `validate.Domain` now enforces the 63-character per-label limit and accepts punycode TLDs (`xn--...`).
- `Version` is a `var` injected via `-ldflags "-X main.Version=$(git describe --tags --dirty)"`. `-version` writes to stdout.
- `go` directive is `1.24.2` (required by charmbracelet/bubbles; a patchless `go 1.24` makes `go build` demand tidy). golangci-lint CI is pinned to v2.12.2. Docker final stage is distroless static nonroot, with builder and runtime images pinned by digest. Tagged releases generate GitHub release notes.

### Removed
- Removed the unused `dns.Resolve` function, superseded by `dns.ResolveTypes`.
- Collapsed the simulation helpers onto `dns.SimulateResolve`, removing the redundant `SimulateResolution` wrapper (its race-detection test was retargeted, not deleted).

### Fixed
- Structured output (`-format json` and `-format csv`) is now finalized only on the successful scan path. The finalizer previously ran via `defer` on every exit, so an early error (such as wildcard detection without `-force`) emitted an empty JSON array. Text output behavior is unchanged.
- `-version` and the startup banner trim a leading `v` from the injected Version so `git describe` tags do not print as `subenum vv0.7.0`.

### Docs
- Rewrote the ARCHITECTURE data-flow section to describe the dispatcher-owned work queue instead of the removed feed-then-close `subdomains` channel model, and corrected the DNS engine function descriptions.
- Refreshed the DEVELOPER_GUIDE: removed "Future Development" items that already shipped, updated the file tree, and corrected `dns` package references.
- Fixed stale references in `DOCUMENTATION_STRUCTURE.md` (changelog path) and README (package blurbs).
- Added `docs/ROADMAP.md` capturing the prioritized review findings and follow-up plan.
- GitHub Pages landing page (`docs/index.md`) covers the 0.7.0 feature set: scan accounting, `-no-abort`, `-max-queries`, the recursion ceiling, and wildcard fingerprint filtering.
- Normalized em dashes to hyphens across `docs/` for consistency with the no-em-dash convention.
- Documented outcome classification, `EventDone.Stats`, and the reliability guard in ARCHITECTURE.
- Corrected ARCHITECTURE output-format note (TUI file output shipped in P5) and DEVELOPER_GUIDE "CLI-only zero deps" claim.

### Tests
- Added TUI coverage: session-config round-trip, form navigation across gated fields, record-type and depth validation, and structured-output finalization on both the success and error paths.
- Added output-writer coverage: file-only writer stdout suppression, simulate-mode text prefix, and the CSV empty-record fallback row.
- Moved the validator tests alongside the new `internal/validate` package.
- Added resolver `Classify` tests and simulate-mode scan tests for outcome accounting, the reliability abort, and `-no-abort`.
- Added a local UDP NXDOMAIN responder test proving `-attempts 3` issues exactly one query for a definitive negative.
- Added a local UDP+TCP responder test proving truncated (TC=1) answers complete over TCP.
- Added wildcard fingerprint tests: matching answers are filtered, and recursive expansion of a wildcard branch is skipped.
- Added tests for `-max-queries` admission, the recursive ceiling refusal, and resolver preflight against a black-holed UDP listener.
- Replaced public-resolver tests with an in-process UDP/TCP responder. Live smoke is gated on `SUBENUM_NETWORK_TESTS=1`.

## [0.6.0] - 2026-06-03

### Added
- Resolved records are now captured during scans. `internal/dns` exposes `Resolve` and a `Record{Type, Value}` type; `scan.Event` carries `Records` for each resolved subdomain (A/AAAA today, extensible to CNAME and more).
- `-format text|json|csv` flag (default `text`, byte-for-byte identical to prior output). JSON emits a buffered array of `{"subdomain", "records"}` objects; CSV streams `subdomain,type,value` rows with a header. The `-o` output file honors the selected format. Output formats are CLI-only for now (TUI-pending).
- `-rate <qps>` flag (default 0 = unlimited) caps total DNS queries per second across the worker pool via a shared stdlib ticker gate inside `scan.Run`. The limiter respects context cancellation so `Ctrl+C` stays responsive.
- `-type A,AAAA,CNAME` flag (default `A,AAAA`, preserving prior behavior) performs per-type DNS lookups and filters results to the requested types. The resolved record type is carried in the existing `Record` shape, so the JSON/CSV schema is unchanged.
- `-recursive` and `-depth <n>` flags for recursive enumeration of discovered subdomains. `scan.Run` was restructured around a dispatcher that tracks outstanding work and closes the queue only when it drains to zero, so resolved subdomains can safely enqueue depth-capped children (the previous close-after-feed shape would have panicked on a send to a closed channel). A centralized visited set provides loop and duplicate protection, and the progress total expands as new work is discovered.

### Changed
- Internal: the scan engine's worker queue lifecycle moved from a feed-then-close channel to a dispatcher-owned queue with a pending-work counter.

## [0.5.1] - 2026-06-03

### Fixed
- Data race in simulation mode: migrated `internal/dns/simulate.go` to `math/rand/v2`, whose top-level functions are goroutine-safe and auto-seeded. `SimulateResolution` is now safe to call concurrently (previously a shared `*math/rand.Rand` was used from every worker).
- Send-on-closed-channel race in `scan.Run`: the progress ticker goroutine now signals its own exit (`tickerStopped`) and guards its send with a select, and `Run` waits for that exit before emitting `EventDone`, so the deferred `close(events)` can no longer race an in-flight ticker send.
- TUI now renders the "Aborted" status when a scan is cancelled with `ctrl+c` (the scan view is marked aborted so the subsequent `EventDone` shows partial counts).
- TUI form no longer blocks a live-mode scan when the Hit Rate field is empty or out of range; hit rate is validated only when Simulate is on.
- `-version` now reports the correct version (`subenum v0.5.1`).
- Docker build: the builder now copies `go.sum` and runs `go mod download` before building, the base image satisfies the module Go version, and `main_test.go` is no longer copied into the build image.

### Changed
- Go minimum version reconciled to 1.24.2 across `go.mod`, the Dockerfile base image, README, and docs (the charmbracelet TUI dependencies require it); direct vs indirect dependency classification corrected via `go mod tidy`.

### Added
- Tests: concurrent `SimulateResolution` test, `internal/scan` runner tests (concurrent simulate run and mid-scan context cancellation), and `internal/tui` form validation tests.

### Docs
- README facelift: plain-text description under the badges, a copy-paste quick-start block, the TUI screenshot promoted to a hero position, PRs-Welcome and platform badges, and removal of em dashes for a clean human-authored look.
- ARCHITECTURE: corrected the progress ticker interval (1 second) and the argument-parsing section (`flag.*Var` into a `cliFlags` struct).
- Removed the unused, duplicate `docs/assets/title.svg`.

## [0.5.0] - 2026-03-14

### Added
- Interactive terminal UI (`-tui` flag) built with Bubble Tea — form-based config screen and live-scrolling results view; no CLI arguments required to launch
- `make tui` Makefile target for one-command TUI launch
- `internal/scan` package: extracted scan engine (`scan.Run`) with typed `Event` channel, usable by both CLI and TUI
- TUI session persistence: last-used form values written to `~/.config/subenum/last.json` and restored on next launch or after pressing `r` (new scan)

### Changed
- CLI scan loop in `main.go` now delegates to `scan.Run()` instead of containing the worker pool inline
- External dependencies added: `github.com/charmbracelet/bubbletea` and `github.com/charmbracelet/bubbles` (TUI only; CLI path has zero external dependencies)
- TUI form field order: Simulate toggle promoted to field 3 (was field 8); Hit Rate row is hidden when Simulate is OFF
- TUI now shows a blinking cursor inside the active text input
- Pressing `r` on the scan results screen returns to the form with last-used values pre-filled (was reset to defaults)

## [0.4.0] - 2026-03-14

### Added
- Wildcard DNS detection with double-probe confirmation; exits by default, continue with `-force`
- Wordlist deduplication (duplicates removed before scanning, count reported in verbose mode)
- `-attempts` flag replacing `-retries` (deprecated, still accepted with warning)

### Changed
- Refactored into `internal/dns`, `internal/output`, `internal/wordlist` packages
- Progress, verbose, and diagnostic output moved to stderr (stdout is now pipe-clean)
- Version bumped to 0.4.0

### Fixed
- Progress ticker no longer corrupts piped stdout output
- `-retries` semantics clarified via rename to `-attempts`

## [0.3.0] - 2026-02-22

### Added
- Output file support with the `-o` flag to save results to a file
- DNS retry mechanism with configurable `-retries` flag for transient failure resilience
- Graceful shutdown on SIGINT/SIGTERM — drains in-flight workers and prints partial results
- Proper DNS server validation (IP format and port range 1-65535)
- Domain format validation against DNS naming rules
- Tests for `validateDNSServer`, `validateDomain`, `resolveDomainWithRetry`, and `simulateResolution`

### Changed
- Removed deprecated `rand.Seed` call (auto-seeded since Go 1.20)
- Tests now use `t.Errorf` for real assertions instead of `t.Logf` warnings
- Fixed test compilation — `resolveDomain` calls now pass all 4 required parameters
- Updated all placeholder URLs/emails in documentation to actual repo values

### Fixed
- Progress goroutine `done` channel is now buffered to prevent potential deadlock
- Mutex-protected stdout/file output to prevent interleaved writes from concurrent workers

## [0.2.0] - 2025-05-08

### Added
- Custom DNS server support with the `-dns-server` flag
- Verbose output mode with the `-v` flag
- Progress reporting during scans (enabled by default)
- Version information accessible via the `-version` flag
- Input validation for concurrency and timeout values
- Legal disclaimers and usage restrictions to prevent misuse
- Comprehensive documentation via README.md and docs folder
- Developer Guide with setup and contribution instructions
- Example wordlist and multi-domain scanning script
- Basic test suite for DNS resolution

### Changed
- Enhanced error handling with user-friendly messages
- Improved code structure and documentation
- DNS resolution now reports timing information in verbose mode

### Fixed
- Proper cleanup of resources after scans complete
- Prevention of negative values for concurrency and timeout

## [0.1.0] - 2025-05-07

### Added
- Initial project setup with basic functionality
- Concurrent subdomain enumeration using goroutines
- DNS resolution with configurable timeout
- Command-line flags for wordlist, concurrency, and timeout
