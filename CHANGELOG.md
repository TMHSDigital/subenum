# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `subenum mcp` serves subdomain enumeration to AI agents over the Model Context Protocol (stdio). Tools: `lab_scan`, which scans the compiled-in lab scenarios on a loopback DNS server; `scan`, offered only with `-allow` and refusing any domain outside it; and `explain_stats`, which explains a `-stats` report or `-format jsonl` output. The operator sets the resolver, rate, timeout and budgets (`-dns-server`, `-rate`, `-timeout`, `-max-queries`, `-max-duration`, which cannot be turned off). A call can lower `max_queries`, never raise it; unknown arguments are refused, and calls run one at a time. Each scan returns its results with a verdict (`complete`, `degraded`, `unreliable` or `not_run`), and sends progress notifications about once a second when the call carries a `progressToken` (#267). `-sources ct,wayback` lets `scan` calls seed candidates from passive sources through a `sources` argument; it is off by default, and the report counts each source's names or names its error (#268). The JSON-RPC layer is a small hand-written `internal/mcp` package, so there is no new dependency (#131).
- `-sources ct,wayback` picks keyless passive sources whose names become candidates and `-permute` seeds, each still verified by a lookup. `ct` is crt.sh, as `-ct`, which stays as shorthand. `wayback` is new: the hostnames in the Wayback Machine's index of archived URLs, one HTTPS request per target. The report gains a `sources` entry per source (`names`, or the `error` it hit; `ct_names` and `ct_error` are kept), a failed source is a warning, the resume state keeps each source's names, simulation ignores `-sources` and lab mode refuses it. Sources share one interface in a new `internal/passive` package. `pkg/subenum` gains `Config.Sources`, the `Source` interface, `CertificateTransparency()`, `WaybackMachine()` and `NoticeSource` (#193).
- `-axfr` tries a zone transfer (AXFR) of each target from its name servers before the scan: the NS records come from `-dns-server`, then each server (up to 8, two addresses each) is asked over TCP. A server that allows it is reported on stderr and in the run-quality report (`axfr_allowed`, `axfr_names`), and the zone's names become candidates and `-permute` seeds, each still verified by a lookup. Refusals, the correct configuration, stay quiet unless `-v`. The NS and address lookups and the transfers count in `queries_sent`; simulation ignores `-axfr`, lab mode refuses it, and a resumed scan reuses the transferred names. The test DNS server can answer AXFR (`Reply.Transfer`) (#85).
- `-axfr` also sends one DNSSEC probe per target to an authoritative server: a query for a name that does not exist, with the DNSSEC OK bit set. A zone that proves the absence with plain NSEC can be walked to list every name, so it is reported as `Zone walkable` on stderr. The report's `zone_denial` says `nsec`, `nsec3` or `none` (unsigned). subenum does not walk the zone. The test DNS server can sign negative answers (`Reply.Denial`) (#234).
- `pkg/subenum` exports `Diff(previous, current []Result, types []string) Changes`: the names added and missing and the names whose records changed, compared the way `-diff-records` does (as sets over the given types, CNAME targets only when an alias is involved). It sends no DNS queries, so `Removed` lists names to look up again rather than names known to be gone. The CLI and the library share the comparison in a new `internal/diff` package (#197).
- The TUI scan view can filter its results: `/` types a name filter, `enter` keeps it, `esc` clears it, and `t` toggles takeover candidates only. While a filter is on the view stops following new results and the hint line says `showing N of M`. The results file is unaffected (#221).
- `-auto-rate` keeps a scan going when its resolver starts rate-limiting: when more than 20% of the last 200 lookups failed, the query rate is halved (from the rate reached so far when `-rate` is 0) with a `rate` notice, and raised again by a quarter at a time, up to where it started, once a window of lookups is healthy. Only after 6 back-offs, or at 5 queries per second, does the reliability guard abort. The report gains `rate_backoffs` and `final_rate`, and `pkg/subenum` gains `Config.AutoRate`, `NoticeRate`, `Stats.RateBackoffs` and `Stats.FinalRate`. Without the flag nothing changes (#220).
- `-type` accepts `NS`, `MX` and `TXT` as well as `A`, `AAAA` and `CNAME`. MX values read `<preference> <host>`. With `NS`, a delegated subzone whose name server does not exist (NXDOMAIN) is marked `dangling-ns`, a classic takeover that CNAME-only scans miss, and `-sarif` reports it under a `subenum/dangling-ns` rule. A recursive resolver usually answers SERVFAIL for a subzone whose every name server is gone, so that case shows up as inconclusive rather than marked. Each new type costs one query per name under `-rate`. The lab scenario format and the test DNS server gain `NS`, `MX` and `TXT` records, and simulation invents MX and TXT records (#194).
- `-takeover-providers <file>` extends the built-in list of takeover-prone services behind `provider:` hints without waiting for a release: one `<suffix> <name>` pair per line, `#` comments allowed. An entry for a listed suffix replaces it, a name of `-` removes the suffix, and the longest matching suffix wins. `-takeover-providers-only` uses the file alone. Bad lines are a usage error naming the line. `pkg/subenum` gains `Config.TakeoverProviders` and `Config.TakeoverProvidersOnly` (#219).
- Results whose addresses are not public are marked with the most notable scope: `loopback`, `unspecified`, `link-local`, `private` (RFC 1918, `fc00::/7`) or `cgnat` (`100.64.0.0/10`). A public name answering with one leaks internal addressing. The scope is an `internal_address` field in JSON and JSONL, `INTERNAL=<scope>` in text with `-show-records`, a tag in the TUI, and an `internal_addresses` count in the breakdown and the run-quality report; CSV is unchanged. Simulated results are never marked. `pkg/subenum` gains `Result.Internal` and `Stats.Internal` (#218).
- `-retry-inconclusive` looks up once more, at the end of each scan, every name whose lookup timed out, was refused or failed, against `-dns-server` (never the `-r` pool). An answer replaces the first outcome in the counts, so a scan with a few dropped packets can still end `complete`; a name that resolves is reported like any other, but not expanded by `-recursive`. The pass is skipped after a reliability abort, an interrupt or once `-max-duration` runs out. `-inconclusive <file>` writes the names still without an answer, one per line, to rescan with `-w`. The report gains `retried` and `recovered` counts, and `pkg/subenum` gains `Config.RetryInconclusive` and `Stats.Retried`, `Stats.Recovered` and `Stats.Inconclusive` (#217).
- Takeover hints recognize two more providers: a CNAME to `*.animaapp.io` is marked `provider:anima` and one to `*.trydiscourse.com` is marked `provider:discourse` (#134, thanks @jdotc1).
- `-log-format json` writes the diagnostics on stderr (notices, warnings, errors, `-v` lines) as JSON Lines, one object per line with `time`, `level` (`error`, `warn`, `notice`, `info`, `debug`), `kind` (`message`, `scan`, `verbose`, `progress`, `simulation`, or an engine notice's category such as `wildcard` or `cap`), the `target` being scanned, the `message`, and the `settings` codes an engine message names (`["max_queries"]`). The simulation banner becomes one `simulation` notice, progress is an event with its numbers and only with an explicit `-progress`, and `-silent` keeps its meaning; results on stdout are unchanged. `SUBENUM_LOG_FORMAT` and the config file set it like any flag (#198).
- `-dry-run` prints what a scan would do without scanning: per target the candidates left after dedupe, invalid entries and `-exclude`, the queries (one per name and record type, and the most with every `-attempts` retry, both capped by `-max-queries`), how long they take at `-rate`, and whether the resolver passes the preflight, which is its only DNS query. `-format json` or `jsonl` prints the plan as JSON. No `-o` file is written, and the run exits 1 only if a preflight fails. `-ct`, `-permute` and `-recursive` add work it cannot count without querying, and it says so (#192).
- `pkg/subenum` exports `Permutations(seeds, words []string) []string`, the candidate generator behind `-permute`: from names already found it returns the nearby variants (`api-dev`, `dev-api`, `dev.api`, `api2`), relative to the apex and ready to pass as a second scan's `Words`. `nil` words selects the CLI's built-in list. It sends no DNS queries (#197).
- `-tui` pre-fills its form from the command line: `subenum -tui example.com -w big.txt -r resolvers.txt` opens with the domain, wordlist and resolver file filled in, over `SUBENUM_*`, config file and remembered values. Flags the form has no field for are named in a warning instead of being dropped silently; the form takes the first `-w`. The form gains **Resolver Pool** (`-r`) and **Rate/Resolver** (`-rate-per-resolver`) fields, remembered in `last.json`. After a scan, `r` restores the values just scanned rather than re-applying the launch flags over them (#195).
- `-rate-per-resolver N` caps the DNS queries per second sent to each `-r` pool resolver, so a high global `-rate` no longer lands in uneven bursts on single members. Lookups go to resolvers with room first and wait only when every cap is spent; `-rate` still caps the total, and the stricter limit wins. The end-of-run resolver table and the report's `resolvers` entries gain a `throttled` count, and `pkg/subenum` gains `Config.RatePerResolver` (#196).
- `-w` can be repeated to layer wordlists, for example a general list plus a target-specific one: `-w general.txt -w target.txt` reads both in order and scans an entry found in both only once (counted as a duplicate, as within one file). `-` stays valid as one of the entries. A `w` value from the config file or `SUBENUM_W` is replaced, not extended, by `-w` on the command line (#199).
- `-max-duration 20m` gives a run a time budget. When it runs out no new names are tested, lookups already under way finish, and the run ends normally: results, the `-stats` report (`stopped_by: "duration"`, untested names in `skipped_by_cap`) and a `degraded` verdict. Under `-dL` one budget covers every target. The GitHub Action gains a `max-duration` input, so a scheduled scan can stop before the job's `timeout-minutes` kills it without a report, and `pkg/subenum` gains `Config.MaxDuration` and `Stats.Expired`. With `-max-queries`, the report now says `stopped_by: "queries"` (#190).
- The progress line and the TUI status bar show an estimated time left (`| ETA 4m12s`), from the rate over the last 30 seconds, once a scan has run for 5 seconds; it disappears at 100% (#191).
- `-diff-records` makes `-diff` compare the records of names found again, so a CNAME re-pointed at an unclaimed service or a moved address is reported as `changed` (`~ name` in text; `"change": "changed"` with `previous_records` in JSON and JSONL), counted in the report's `diff.changed`, and exits 4. When either side has a CNAME only the alias targets are compared, so CDN address rotation is not a change. The previous file must be JSON, JSONL or CSV. The GitHub Action gains a `changed` output (#189).

### Changed
- The TUI runs on Bubble Tea v2: `charm.land/bubbletea/v2` v2.1.1, `bubbles/v2` v2.2.1 and `lipgloss/v2` v2.0.6 replace the v1 modules, dropping v1-only helpers that had not had a release in years. Keys, screens and the form work as before; the `go 1.26.0` minimum is unchanged (#188).
- With text output (the default) and no `-show-records` or `-diff`, the CLI keeps only the names of the current target's results for `-permute` and the `-resume` state, plus the few results with a takeover hint, an internal address or a permutation, instead of every result with its records. A simulated 1M-name scan at 100% hits peaks at about 240 MB instead of 750 MB, against 233 MB at 1% hits. A resumed run re-emits the same text. Structured formats still keep the records a resumed run writes back (#183).
- The scan dispatcher hands jobs to workers in small chunks (up to 8, fewer when there are few names per worker) over buffered channels, and each worker reports a chunk's jobs at once, instead of two unbuffered hand-offs per job. A 1M-name simulated scan at 50 workers (`make bench`) takes about 0.4 s instead of 1.6 s. A resumed scan may repeat up to one chunk per worker instead of one lookup per worker (#184).
- Live UDP scans reuse sockets instead of opening and closing one per query, which capped throughput near 10k queries per second with nearly all CPU in socket teardown. A 100k-name scan against a loopback server now takes about 2 s instead of 12 s at `-t 200`. A late answer to an earlier query on a reused socket is ignored, as before, and cannot make a lookup count as refused (#180).
- `-format json` streams its array instead of holding every result and then encoding the whole document, so its peak memory matches `-format jsonl` (a 300k-result run: about 200 MB instead of 420 MB). The output is byte for byte the same (#181).
- The wordlist is normalized once per run instead of once per `-dL` target: `wordlist.Prepare` normalizes the lines and `Prepared.For` applies only each target's 253-character limit. On a 1M-line list, normalizing takes about 0.5 s instead of 0.8 s with almost no allocations, and each further target about 0.5 ms. Results and counts are unchanged (#182).
- Tests no longer flake under load: lab end-to-end runs use a 5 s timeout with 3 attempts and fail with a clear message if the lab 2 wildcard probe times out, the resolver-pool spread test counts lookups per member instead of timing the scan (the timing view is now `BenchmarkPoolSpreadsLoad`), and CI runs tests in shuffled order (#167).

### Fixed
- On Windows, `-o NUL`, `-stats NUL` and `-sarif NUL` no longer fail with "Incorrect function" and exit 1: device and pipe targets are opened without truncation (#208, thanks @bfs2021).
- An unreadable `-seeds` file no longer leaves a hidden `.<name>.tmp` file beside the `-o` path (kept locked on Windows until exit): seeds are read before the output file is opened (#212).
- On Windows, `-simulate-zone` labs and the test DNS server no longer fail to start about a quarter of the time with "no free UDP+TCP port pair": after a failed TCP bind the server retries on random ports instead of the next OS-assigned one, which stayed inside the same reserved port block (#204).
- A `scan.Config` built directly with `Attempts: 0` now makes one attempt per name instead of passing preflight and then failing every lookup without a query. Scan workers, `scan.Verify` and the wildcard near-miss probes share one resolve path (test hook, simulation, or the trusted resolver), and the `internal/dns` lookup helpers take a `dns.Lookup` value (resolver, timeout, attempts, types, logger) instead of long positional parameter lists, so a swapped attempts/types argument no longer compiles (#163).
- `-rate-per-resolver` (and `pkg/subenum`'s `RatePerResolver`) now holds: each pool lookup books one slot per DNS query it sends, as `-rate` does, instead of one per record type. The default A and AAAA lookup from the library booked one slot for two queries, and a CNAME lookup one for three, so members got up to twice the cap (#236).
- `-diff`'s check of previous names this run did not find now stays within the run's budgets: it looks up at most what is left of `-max-queries` (per target, less the names tested) and stops at the `-max-duration` deadline, counting the names it does not reach as `unverified`. A large baseline could otherwise send far more queries, and run far longer, than the budget allowed (#276).
- `-resume` no longer skips names when a passive source failed in the interrupted run and works on resume. The failed source was fetched again, its names were inserted before later sources' names, and the saved position then pointed past candidates that were never tested while the verdict could still read `complete`. The resume state now records a failed source with no names, and the resumed run replays that (#237).

### Security
- `go.mod` names a patched toolchain (`toolchain go1.26.11`) beside the unchanged `go 1.26.0` floor, so `go install` and the action's `version: source` build with the security-fixed `net/http`, `crypto/tls` and `crypto/x509` instead of the original 1.26.0 standard library; with the default `GOTOOLCHAIN=auto` an older local Go fetches it. Release binaries were already built with a current Go (#243).
- The GitHub Action checks the downloaded release archive's build provenance with `gh attestation verify` as well as its `checksums.txt`, since an archive and its checksums file could be replaced together. The Pages workflow grants `pages: write` and `id-token: write` only to the job that deploys, not to the whole workflow (#210).

## [0.10.0] - 2026-11-08

### Changed
- Engine messages no longer hard-code command-line flags. They name settings with neutral tokens (`scan.Setting`), and each front end renders them in its own terms: the CLI as flags (unchanged output), the TUI as its form labels ("Use Force to scan anyway", "invalid Exclude pattern"), and `pkg/subenum` as `Config` fields, replacing its regexp that guessed flags out of message text. A test fails if an engine message names a flag or uses an unknown token (#100).
- The scan engine always ends with exactly one done event, marked `Stopped` when the scan ended before testing any candidate (out of scope, recursion ceiling, failed preflight or wildcard check, a wildcard zone without `-force`, or Ctrl+C during those checks), so the CLI, the TUI and `pkg/subenum` handle one shape of ending instead of a channel that sometimes closes without one. `pkg/subenum`'s `Event` gains `Stopped`, and a stopped scan's `Stats` now include the queries its checks sent (#99).
- `-retries`' deprecation warning goes through the normal output, so `-silent` hides it (#166).
- The container image is built with Go 1.27.3 (from 1.27.1, picking up `crypto/tls` and `crypto/x509` fixes the `-ct` client uses) on a refreshed distroless base (#185). `golang.org/x/net` is v0.62.0 and indirect modules are on their latest patches; the `go 1.26.0` minimum is unchanged (#186).
- CI pins govulncheck and the devcontainer images, which Dependabot now updates, and lints with golangci-lint v2.15.0 (#187).

### Fixed
- With `-r`, a retry goes back to the healthy resolver it just used rather than to one that is benched as dead, so a pool with one live resolver no longer turns transient timeouts into failures (#148).
- `pkg/subenum`: `Scan` with `NoAbort` returns no error for a scan that ran to completion; the reliability warning is still sent by `Run` as a `KindError` event (#149).
- `-simulate` no longer contacts crt.sh when `-ct` is set: CT seeding is skipped with a note, keeping the promise that nothing leaves the machine (#150).
- `-diff` interrupted while re-checking previous names counts the names it never checked as unverified instead of still resolving (#151).
- `-exclude` accepts internationalized patterns such as `mail.bücher.de` and matches them in punycode, as targets are scanned (#152).
- `pkg/subenum`: a simulated scan with `Seed` 0 picks a random seed, as documented, instead of always using 0 (#154).
- A resumed scan counts names it finds again after the resume point only once in `found` and `processed` (#156).
- The TUI keeps reading scan events when the engine sends a kind it does not know, instead of stalling (#165).
- `-resume=` with no path is a usage error, and `-resume` after `--` is treated as an argument (#166).
- The TUI exits 1 when the results file could not be written, as the CLI does, instead of 0 with only an on-screen message (#155).
- `-print-config` shows the `attempts` value a scan actually uses: `1` by default instead of the raw `0` sentinel, and the `-retries` value (marked `from retries`) when that is what wins (#153).
- `tools/wordlist-gen` parses flags that appear after a positional the same way `subenum` does, instead of silently ignoring both: a leftover argument is now a usage error (2) that points at `-domain`, and an invalid `-combine` value or an empty `-o` exits 2 instead of 1 (#120).

## [0.9.0] - 2026-10-06

### Added
- A GitHub Action: `uses: TMHSDigital/subenum@<release>` installs a release verified against `checksums.txt`, diffs against the previous complete run (kept as an artifact, or a `previous` file), can write SARIF, writes a job summary table, exposes `verdict`/`found`/`added`/`removed` outputs and fails the job on a configurable verdict. CI runs it from the checkout against a lab zone on Linux, macOS and Windows (#126).
- Certificate Transparency seeding: `-ct` adds the names crt.sh knows under each target (one HTTPS request, no API key) as candidates after the wordlist and as `-permute` seeds; every name is still resolved before it is reported. A crt.sh outage is a warning, the report gains `ct_names` and `ct_error`, a resumed scan reuses the fetched names, and lab mode refuses `-ct` (#130).
- `-sarif <file>` writes takeover candidates as a SARIF 2.1.0 log (validated against the OASIS schema): one rule per kind of finding, with a security severity, the CNAME target in the message and a stable fingerprint per name, ready for `github/codeql-action/upload-sarif`. The Monitoring page shows the upload step (#129).
- `-silent` for pipelines: bare result names on stdout and nothing on stderr but errors and a one-line warning when results are simulated. A new [Pipelines](docs/pipelines.md) page chains subenum with dnsx, httpx and nuclei and gates each step on the run-quality verdict (#128).
- A Go library API, `pkg/subenum`, so other programs can embed the engine: `Config` (every zero value takes the CLI's default), `Scan` for a finished run, `Run` to stream `Event` values, and `Result`, `Record` and `Stats`. The DNS internals stay unexported, engine messages name `Config` fields instead of CLI flags, and `Run` always ends with one terminal event carrying the final `Stats`. Runnable examples ship for pkg.go.dev (#77).
- Lab mode: `-simulate-zone <file>` answers every query from a scenario file (names, A/AAAA/CNAME records, wildcards, TIMEOUT/SERVFAIL/REFUSED/NXDOMAIN failures, `$DELAY` and `$REFUSE-ABOVE` rate limiting) through a DNS server on `127.0.0.1`. The real resolver, wildcard detection, `-rate`, takeover hints and the run-quality report run unchanged, deterministically and without traffic leaving the machine. A new [Labs](docs/labs.md) page has five guided exercises with answers, and the scenarios ship in `examples/labs/`. The run-quality report gains a `zone` field (#76).
- Contributor experience: a devcontainer (Go 1.26 plus the CI golangci-lint) with an "Open in Codespaces" badge, YAML issue forms with blank issues disabled and contact links to private vulnerability reporting and Discussions, `FUNDING.yml` and `CITATION.cff` (#75).
- Encrypted DNS transports: `-dns-server tls://host[:853]` (DNS over TLS, with pooled connections) and `-dns-server https://host/path` (DNS over HTTPS, RFC 8484, keep-alive and HTTP/2). Records, outcome classification (including REFUSED and timeouts) and `-rate` accounting are identical to UDP, and the run-quality report gains a `transport` field (#86).
- Resumable scans: an interrupted run (Ctrl+C, SIGTERM) saves its state to `subenum-resume.json` (or `-state <file>`), and `subenum -resume <file>` replays the original command line, checks the input files are unchanged, restores the earlier results and continues from the first wordlist entry not yet fully looked up. The scan engine tracks that low-water mark exactly even though workers finish out of order, so at most a worker pool's worth of lookups is repeated (#73).
- Permutation mode: `-permute` follows each target's scan with a second pass over permutations of the names found (word joins such as `api-dev`, `dev-api` and `dev.api`, and number increments), and `-seeds <file>` adds seeds from an earlier run in any format. The pass is fully guarded (preflight, wildcard filtering, `-rate`, `-max-queries`, `-exclude`), skips wordlist entries, marks its hits `"permutation": true`, and reports seeds, candidates and hits in the run-quality report (#72).
- Defaults from a config file and the environment: `config.json` in the user config directory (or `$SUBENUM_CONFIG`) and `SUBENUM_<FLAG>` variables, with precedence flag > env > config > built-in. `-print-config` shows each effective setting and its source. `subenum completion bash|zsh|fish|powershell` and `subenum man` generate shell completions and a man page from the flags, and release archives ship them (#88).
- A useful default wordlist: `-w` is now optional. Without it, subenum uses an embedded list of the 5,000 most common subdomain labels (SecLists `subdomains-top1million-5000.txt`, MIT; the license notice is kept in `data/subdomains-5k.txt`) and says so on stderr. The README gains a "Choosing a wordlist" section on larger lists and their query cost (#63).
- Monitoring mode: `-diff previous` compares with an earlier results file (any format) and prints only names added (`+` / `"change": "added"`) or removed (`-` / `"removed"`), with a `change` CSV column; exit code `4` signals changes. The `-o` file keeps the full current results for the next run. Removals are reported only when the run's verdict is `complete`, and never for `-exclude`d names. The run-quality report gains a `diff` object, and `docs/monitoring.md` has a scheduled GitHub Actions workflow that opens an issue for new names (#84).
- Subdomain takeover hints: results with a CNAME are marked `dangling` (target is NXDOMAIN), `provider:<name>` (target at a takeover-prone service such as S3, GitHub Pages, Heroku or Azure) or `dangling:<name>`. The marker appears in JSON/JSONL (`takeover_candidate`), as a CSV column when CNAME records are requested, in text with `-show-records`, in the TUI, and as a count in the breakdown and report. DNS-only; no HTTP probing (#71).
- Resolver pool: `-r resolvers.txt` spreads lookups over many resolvers, round-robin over the healthy ones (a resolver failing over half its recent lookups is benched for 30s), with retries sent to a different resolver. Every pool hit is re-validated against `-dns-server`, whose answer is reported, so a lying pool resolver cannot inject results. Per-resolver accounting appears in a stderr table and in the run-quality report, with `pool_hits` / `confirmed` / `unconfirmed` per target. In a hermetic test, 20 rate-limited resolvers ran the same scan 14x faster than one (#69).
- Scope control: `-exclude 'vpn.example.com,*.corp.example.com'` and `-exclude-file` keep out-of-scope names out of a scan. Excluded names are never queried, wildcard-probed or expanded recursively (a found parent whose whole subtree is excluded costs no queries), they are counted as `excluded` in the breakdown and the run-quality report, and a target that is itself out of scope is refused. The TUI has a matching Exclude field (#87).
- Run-quality report: `-stats <file>` writes a schema-versioned JSON summary of a run (outcomes per target, DNS queries actually sent, achieved query rate, wildcard fingerprint, candidates skipped by `-max-queries`) with a `complete` / `degraded` / `unreliable` verdict and its reason. `-format jsonl` ends with the same object as its last line. The README documents the schema and how to gate CI on the verdict (#70).

### Changed
- The site publishes a `sitemap.xml` (jekyll-sitemap) and a JSON-LD `SoftwareApplication` block on the home page; it redeploys only when `docs/` changes or a release is published, and the build fails on a broken internal link or `#anchor` (`.github/scripts/check-links.py`) (#125).
- The website is redesigned and rebranded: a new mark and wordmark (an apex branching into resolved and NXDOMAIN names), a palette built from the outcome colours, a landing page that replays a scan and explains the three verdicts, and a docs layout with a sidebar, on-page contents, previous/next links, client-side search (`/` or Ctrl+K), light and dark themes and a 404 page. New pages: Getting started, CLI reference (the flag table moves off the home page) and Go library. Navigation is driven by `docs/_data/nav.yml`; the Developer Guide explains how to preview the site locally.
- Releases are built by GoReleaser from `.goreleaser.yaml`: static, trimmed binaries for Linux, macOS, Windows and FreeBSD (adding windows/arm64, linux/386 and FreeBSD) packed in `.tar.gz`/`.zip` archives with LICENSE, README and CHANGELOG, plus `checksums.txt`, an SPDX SBOM per archive, a keyless cosign signature over the checksums, build-provenance attestations, and release notes taken from the tag's CHANGELOG section. The release stays a draft until provenance is attested. CI runs the same pipeline in snapshot mode on every push to main. Asset names change from `subenum-linux-amd64` to `subenum_<version>_linux_amd64.tar.gz` (#61).
- The GitHub Pages site is current: the hero shows real output (resolved names only), the flag table is generated from the CLI's own flags (a test fails when it drifts; `make docs-flags` regenerates it), the features cover the run-quality report, resolver pool, takeover hints, monitoring and scope control, there is a GHCR quick start and a Monitoring page, shared links get `og:`/Twitter preview cards with a new social image, the internal `DOCUMENTATION_STRUCTURE.md` template is no longer published, and the unused Cayman theme is gone. The README's "Why subenum" is updated to match (#64).
- Tests run against a shared, scriptable DNS server, `internal/dnstest`, built on `golang.org/x/net/dns/dnsmessage`. It replaces the two hand-encoded responders, answers per name and type with records, any RCODE, NODATA with SOA, delays, drops or truncation, and counts queries per name and type. New tests cover NODATA, a resolver at an IPv6 address, exact wire queries per record type, and TCP fallback after truncation (#67).
- The minimum Go version is now 1.26 (`go 1.26.0` in go.mod), required by current `golang.org/x/sys` and `golang.org/x/text`; both were bumped and `govulncheck -show verbose` now reports no vulnerable modules. Dependabot also updates indirect modules, and CI lints with errorlint, nilerr, contextcheck, noctx, copyloopvar, usestdlibvars and revive, with errcheck exemptions narrowed to stdout prints (#83).

### Fixed
- The TUI writes the same files as the CLI: a CSV gets the `takeover_candidate` column when CNAME records are requested, and a JSONL file ends with the run-quality summary line. Its form starts from `SUBENUM_*` and config-file values, over the values remembered from the last session. The report is built by a new `internal/report` package that both front ends share (#118).
- Shell completions: `-simulate-zone`, `-seeds`, `-resume` and `-state` complete file names in every shell (fish previously disabled file completion for them), bash and fish complete the shell name after `completion`, and the PowerShell completer reads the previous word, so file flags fall back to path completion and `-format`/`-type` offer their values. A test fails when a flag that takes a file is missing from the list, and CI checks that every generated script parses in its shell (#117).
- New `-o` and `-stats` files get 0666 less the umask, as `os.Create` would, instead of a fixed 0644, so results stay private under `umask 077`; an `-o` path that is a symlink keeps the link and replaces the file it points at, instead of turning into a regular file (#119).
- Takeover hints resolve each CNAME target once per scan instead of once per result, so hundreds of names aliased to the same CDN or SaaS host no longer spend a query and a `-rate` slot each; concurrent results for one target share the lookup, and an inconclusive one is retried by the next name (#121).
- DoT connection reuse is accurate: a pooled connection the server already closed is detected before reuse instead of failing a query that had already been counted and paced (a server closing after each answer cost 19 dials for 10 lookups; now 10). Up to 128 connections are kept, matching the default `-t`, and a scan closes its idle DoT and DoH connections when it ends, so a program that scans repeatedly through `pkg/subenum` does not hold them open (#113).
- DNS over HTTPS never follows a redirect, so a misconfigured endpoint or proxy cannot move the query elsewhere or downgrade it to cleartext `http://`; HTTP 429 and 503 count as `refused` (the rate-limit signal) instead of `other` (#114).
- `-dns-server tls://[2001:db8::1]` (a bracketed IPv6 host without a port) is accepted; the validator and the dialer now share one parser. Lab zone CNAME targets are validated, and `CNAME @` points at the scanned domain instead of the bogus `@.<domain>` (#115).
- The test DNS server's `Close` waits for every handler, closes open stream connections, and no longer returns while delayed UDP answers or connections parked on a dropped query are still running. New tests cover an untrusted DoT certificate, DoH redirects and throttling, stale pooled connections, a lying pool member and the server's own lifecycle (#122).
- `pkg/subenum.Run` no longer leaks the scan's worker pool when a caller breaks out of the event loop and cancels without draining (about 100 goroutines per run before): after cancellation the forwarder never waits for a reader, so every goroutine exits within about a second. `DefaultWords` parses the bundled list once, and a positive `Timeout` below 1ms is rounded up instead of being rejected as 0 (#112).
- A resolver pool member that answers NXDOMAIN for names that exist can no longer silently hide them. Each member is checked with canaries (names the trusted resolver confirmed, starting with the apex), and an NXDOMAIN from a member that has not passed a canary is confirmed by a second member. A member contradicted three times (a hidden name, a failed canary, or a hit the trusted resolver denies) is flagged and dropped for the rest of the run; the per-resolver report gains `canaries`, `contradicted` and `flagged`. In a hermetic test, one always-NXDOMAIN member previously hid half the real names; now none are lost. In a zone with no known name to use as a canary, NXDOMAIN answers cost a second pool query until one is found (#105).
- `-diff` no longer reports names this run never tested as removed. Every previous name the run did not find is looked up again with the trusted resolver, and only NXDOMAIN counts as removed; names that still resolve (a smaller wordlist, no `-recursive` or `-permute`, now wildcard-filtered) or whose lookup fails are counted as `still_resolving` and `unverified` in the report's `diff` object instead (#110).
- Resuming a `-permute` scan no longer skips the permutation pass: the main pass's resume position was applied to the permutation candidates, so a resumed pass queried nothing. The pass now saves and resumes from its own position, and is seeded only with the main pass's names so the resumed candidate list is identical (#107).
- `-max-queries` covers a scan across interrupts: a resumed pass gets only the budget left, and none once it is spent. Previously each resume started a fresh budget (#108).
- Resume state is more robust: a resumed scan interrupted again during preflight keeps the earlier resume point and statistics instead of restarting from entry 0, targets a run never reached keep their state, and a resume is refused when the normalized wordlist (including the bundled one), an effective setting from `SUBENUM_*` or the config file, or a `-simulate-zone`, `-seeds` or `-diff` file changed. A resumed run that finishes deletes its state file (#109).
- `-permute` with `-recursive` runs the permutation pass one level deep, instead of expanding found permutations with the candidate list (names such as `<candidate>.api-dev.<target>`) and being refused past the recursion ceiling; candidates longer than 253 characters are skipped instead of failing as `other` (#111).
- Lab mode can no longer send queries off the machine: `-r`, `-dns-server` or `-simulate` from a `SUBENUM_*` variable or the config file is refused with `-simulate-zone` just like the flag, naming where the value came from. Previously `SUBENUM_R` sent every lab query to the listed resolvers under a "no traffic leaves this machine" banner (#106).
- Config and environment defaults: `-h`, `-version`, `-print-config` and `-tui` work despite a bad value; every bad value is reported at once; config values must be strings, numbers or booleans (`exclude` and `type` also take a list) instead of being stringified into values such as `<nil>`; `resume` is refused in the config file; `-attempts` and `-retries` from different sources resolve by precedence instead of conflicting; and `SUBENUM_PROGRESS` counts as an explicit `-progress` (#116).
- An unreadable `-r` file exits 1 like every other unreadable input file (a malformed one is still a usage error, 2), and argument errors are reported before the simulation banner is printed or any resolver list is read (#120).
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

[Unreleased]: https://github.com/TMHSDigital/subenum/compare/v0.10.0...HEAD
[0.10.0]: https://github.com/TMHSDigital/subenum/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/TMHSDigital/subenum/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/TMHSDigital/subenum/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/TMHSDigital/subenum/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/TMHSDigital/subenum/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/TMHSDigital/subenum/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/TMHSDigital/subenum/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/TMHSDigital/subenum/releases/tag/v0.4.0
