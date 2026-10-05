<div align="center">

<img src="docs/assets/wordmark.svg" alt="subenum" width="600"/>

<br>

[![Build](https://img.shields.io/github/actions/workflow/status/TMHSDigital/subenum/go.yml?branch=main&style=for-the-badge&label=build)](https://github.com/TMHSDigital/subenum/actions)
[![Release](https://img.shields.io/github/v/release/TMHSDigital/subenum?style=for-the-badge)](https://github.com/TMHSDigital/subenum/releases)
[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg?style=for-the-badge)](LICENSE)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/TMHSDigital/subenum/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/TMHSDigital/subenum/actions/workflows/codeql.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/TMHSDigital/subenum?style=for-the-badge&v=0.8.0)](https://goreportcard.com/report/github.com/TMHSDigital/subenum)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=for-the-badge)](./docs/CONTRIBUTING.md)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge)](#installation)

<br>

**Fast concurrent subdomain enumeration, written in Go.** Point it at a domain and a wordlist; it brute-forces DNS across a worker pool and prints the subdomains that resolve. Built for pentesters, bug-bounty hunters, and operators doing authorized reconnaissance of their own infrastructure.

<br>

<img src="docs/assets/tui-form.png" alt="subenum interactive TUI" width="640"/>

<br>

[Quick Start](#quick-start) &nbsp;|&nbsp; [Configuration](#configuration) &nbsp;|&nbsp; [Usage](#usage) &nbsp;|&nbsp; [Architecture](#system-architecture) &nbsp;|&nbsp; [Changelog](./CHANGELOG.md)

</div>

<br>

---

> [!IMPORTANT]
> **Authorized use only.** Only scan domains you own or have explicit written permission to test. Unauthorized scanning may violate applicable laws. Users are solely responsible for compliance with all applicable laws and regulations.

---

<br>

## Quick Start

```bash
go install github.com/TMHSDigital/subenum@latest
```

Or build from a clone, which also gives you the sample wordlists used below:

```bash
git clone https://github.com/TMHSDigital/subenum.git
cd subenum
go build -buildvcs=false -o subenum
./subenum -w examples/sample_wordlist.txt example.com
```

No network required to try it out. Simulation mode generates synthetic results with zero DNS queries:

```bash
./subenum -simulate -hit-rate 20 -w examples/sample_wordlist.txt example.com
```

Or launch the interactive terminal UI with no flags:

```bash
./subenum -tui
```

<br>

## Why subenum

Tools like [puredns](https://github.com/d3mondev/puredns), [shuffledns](https://github.com/projectdiscovery/shuffledns) and [dnsx](https://github.com/projectdiscovery/dnsx) are faster at mass resolution across large resolver pools, and [subfinder](https://github.com/projectdiscovery/subfinder) covers passive sources. subenum is a single static binary that brute-forces against one resolver you choose and focuses on telling you how much to trust the result:

- **It accounts for every query.** Each lookup is classified as resolved, nxdomain, timeout, refused or other, and the breakdown is printed after every scan. When more than 20% of queries fail, the scan stops and blames the resolver instead of returning a quietly incomplete list.
- **It handles wildcards.** Wildcard DNS is detected before the scan starts. With `-force`, answers matching the wildcard fingerprint are dropped, and recursive scans skip wildcard branches.
- **Its rate limit is real.** `-rate` caps DNS packets on the wire, including retries, every record type and wildcard probes, so it can be quoted in rules of engagement.
- **It can be taught and demoed.** `-simulate` produces realistic output with zero network traffic, and `-tui` gives a form-driven interface for people who don't live in a shell.

<br>

---

<br>

## Feature Matrix

| Module | Description |
| :--- | :--- |
| Worker Pool | Spawn N goroutines for parallel DNS resolution with a configurable concurrency ceiling |
| DNS Engine | Resolve subdomains against any DNS server with per-query timeouts and retry backoff |
| Wildcard Detection | Double-probe check before scanning; aborts early unless `-force` is set. With `-force`, answers that match the wildcard fingerprint are dropped |
| Scan Accounting | Every query is counted as resolved, nxdomain, timeout, refused, or other. After 200 queries a >20% infrastructure failure rate aborts unless `-no-abort` is set |
| Query Cap | `-max-queries` stops admitting work. Recursive scans warn about the theoretical ceiling and refuse to start above 1e7 jobs unless `-max-queries` or `-force` is set |
| Graceful Shutdown | Trap SIGINT/SIGTERM, drain in-flight workers, flush partial results |
| Input Validation | RFC-compliant domain syntax and strict `ip:port` format enforcement |
| Wordlist Hygiene | Normalize the wordlist in one pass before scanning: skip blank lines and `#` comments, lowercase, deduplicate, and drop entries that are not valid DNS labels or would exceed 253 characters |
| Simulation Mode | Generate synthetic DNS results at a configurable hit rate, with zero network I/O |
| Output Pipeline | Resolved domains to stdout (pipe-clean); progress and diagnostics to stderr |
| Output Formats | Emit results as `text`, `json` (array of subdomain plus typed records), streaming `jsonl`, or `csv` via `-format`; `-show-records` adds record values to text output |
| Rate Limiting | Cap DNS queries per second on the wire with `-rate`: every record type, retry and wildcard probe takes a slot, and queueing never eats into `-timeout` |
| Record Types | Look up and filter by `A`, `AAAA`, or `CNAME` records with `-type` |
| Recursive Enumeration | Enumerate subdomains of discovered subdomains with `-recursive` and a `-depth` cap, with loop and duplicate protection |
| Interactive TUI | Form-based config and live-scrolling results via `-tui`; session values persisted |

<br>

---

<br>

## System Architecture

```mermaid
flowchart LR
    subgraph Input
        A[Wordlist File] -->|"dedup + load"| B(Entry Slice)
        C[CLI Flags / TUI Form] --> D(Argument Parser)
    end

    subgraph PreScan
        D --> W{Wildcard\nDetection}
        W -->|"no wildcard / -force"| E
    end

    subgraph Engine
        B --> E{Worker Pool\nN Goroutines}
        E -->|subdomain.domain| F[DNS Resolver]
        F -->|retry + backoff| F
        G[Context] -->|cancel| E
        G -->|timeout| F
    end

    subgraph OutputLayer ["Output"]
        F -->|resolved| H["stdout (results)"]
        F -->|resolved| I[Output File]
        E -->|atomic counters| J["stderr (progress)"]
    end

    K[SIGINT / SIGTERM] -->|cancel| G
```

<br>

---

<br>

## Installation

**Prerequisites:** Go 1.24+ &middot; Git &middot; Make _(optional)_ &middot; Docker _(optional)_

<details>
<summary><strong>go install</strong></summary>

```bash
go install github.com/TMHSDigital/subenum@latest
```

Requires Go 1.24.2 or newer. The binary lands in `$(go env GOPATH)/bin` and reports the installed module version with `-version`.

</details>

<details>
<summary><strong>Build from source</strong></summary>

```bash
git clone https://github.com/TMHSDigital/subenum.git
cd subenum
go build -buildvcs=false -o subenum
```

</details>

<details>
<summary><strong>Pre-built binaries</strong></summary>

Download the appropriate binary for your platform from the [Releases](https://github.com/TMHSDigital/subenum/releases) page.

Platforms: Linux (amd64, arm64) &middot; macOS (amd64, arm64) &middot; Windows (amd64)

SHA-256 checksums are provided alongside each binary.

</details>

<details>
<summary><strong>Docker</strong></summary>

Releases from v0.8.0 onward publish a multi-arch image (`linux/amd64`, `linux/arm64`) to GHCR:

```bash
docker run --rm -v "$(pwd)/data:/data" ghcr.io/tmhsdigital/subenum:latest -w /data/wordlist.txt example.com
```

Or build it locally:

```bash
docker build -t subenum .
docker run --rm -v $(pwd)/data:/data subenum -w /data/wordlist.txt example.com
```

Or with Compose:

```bash
docker compose run --rm subenum            # simulated demo, no DNS traffic
docker compose run --rm subenum -w /data/wordlist.txt yourdomain.com   # live
```

</details>

<details>
<summary><strong>Make targets</strong></summary>

```bash
make build          # compile binary
make test           # run test suite with race detector
make lint           # run golangci-lint
make simulate       # safe run - no DNS queries
make tui            # launch interactive TUI
make docker-build   # build Docker image
make help           # list all targets
```

</details>

<br>

---

<br>

## Configuration

### CLI flags

| Flag | Default | Description |
| :--- | :---: | :--- |
| `-w <file>` | n/a | Wordlist file, one prefix per line; `#` comments allowed; `-` reads stdin **(required)** |
| `-dL <file>` | n/a | File of apex domains to scan, one per line (`-` reads stdin), instead of a `<domain>` argument. Each domain is an independent scan; results share one output |
| `-t <n>` | `100` | Concurrent worker goroutines |
| `-timeout <ms>` | `1000` | DNS timeout in milliseconds, applied to each record-type lookup separately |
| `-dns-server <ip:port>` | `8.8.8.8:53` | DNS server address (validated on startup) |
| `-attempts <n>` | `1` | DNS resolution attempts per subdomain (1 = no retry) |
| `-force` | `false` | Continue scanning even if wildcard DNS is detected |
| `-no-abort` | `false` | Keep scanning after the 20% resolver failure-rate abort (warning is still emitted) |
| `-max-queries <n>` | `0` | Max candidate names to test (0 = unlimited). Each name sends one query per record type per attempt (`CNAME` costs two) |
| `-o <file>` | n/a | Write results to file in addition to stdout |
| `-format <fmt>` | `text` | Output format: `text`, `json`, `jsonl` (one object per line, streamed), or `csv` |
| `-show-records` | `false` | In `text` format, append each result's records as `TYPE=value` |
| `-rate <qps>` | `0` | Max DNS queries per second on the wire, all workers combined, including every record type, retry, wildcard probe and the preflight (0 = unlimited) |
| `-type <list>` | `A,AAAA` | Comma-separated record types to look up: `A`, `AAAA`, `CNAME` |
| `-recursive` | `false` | Recursively enumerate subdomains of discovered subdomains |
| `-depth <n>` | `1` | Max recursion depth when `-recursive` is set (1 = no recursion) |
| `-v` | `false` | Verbose output: IPs, timings, per-query detail (stderr) |
| `-progress` | `true` | Live progress line on stderr. Off by default when stderr is not a terminal; passing `-progress` there prints whole progress lines instead of redrawing one |
| `-simulate` | `false` | Simulation mode: no real DNS queries |
| `-hit-rate <n>` | `15` | Simulated resolution rate, percent (1-100), applied uniformly to every name |
| `-seed <n>` | `0` | Simulation seed; the same seed reproduces the same results (line order can vary unless `-t 1`). `0` picks a random seed and prints it |
| `-tui` | `false` | Launch the interactive Terminal UI |
| `-version` | n/a | Print version and exit |
| `-retries <n>` | n/a | **Deprecated** - alias for `-attempts`, prints a warning |

<br>

> [!NOTE]
> Wildcard DNS is detected automatically before scanning begins. If the target resolves wildcard records, or the wildcard probes fail so the check is inconclusive, the tool exits with a warning, since all subdomains would match, making results meaningless. Pass `-force` to override. With `-force`, results whose records are a subset of the wildcard fingerprint are still dropped and counted as `wildcard-filtered`. The fingerprint comes from several random probes, and when the wildcard answers from a rotating CDN or load-balancer pool, subenum keeps probing until it has learned the pool; a result that shares only some records with the fingerprint is re-checked against fresh probes. Recursive scans probe each new parent and skip expanding wildcard branches.

> [!CAUTION]
> Simulation mode (`-simulate`) generates synthetic results and performs zero network I/O. Do not confuse simulated output with real DNS data. Simulated output marks itself: JSON and JSONL results carry `"simulated": true`, CSV gets a `simulated` column, and `-o` text files start with a `# SIMULATED` comment line. Bare names piped to stdout stay unmarked so they still pipe cleanly.

<br>

---

<br>

## Usage

### CLI

```bash
subenum -w <wordlist> [flags] <domain>
subenum -w <wordlist> [flags] -dL <domains_file>
```

<details>
<summary><strong>Examples</strong></summary>

**Basic scan**
```bash
./subenum -w wordlist.txt example.com
```

**High-throughput with Cloudflare DNS, saving results**
```bash
./subenum -w wordlist.txt -t 300 -timeout 500 -dns-server 1.1.1.1:53 -o results.txt example.com
```

**Resilient scan for flaky networks**
```bash
./subenum -w wordlist.txt -attempts 3 -timeout 2000 example.com
```

**Pipe-friendly - only resolved subdomains on stdout**
```bash
./subenum -w wordlist.txt example.com | your-takeover-scanner
```

**Force scan on a wildcard domain**
```bash
./subenum -w wordlist.txt -force example.com
```

**Simulation - zero network I/O**
```bash
./subenum -simulate -hit-rate 20 -w examples/sample_wordlist.txt example.com
```

</details>

Press `Ctrl+C` at any time to abort. In-flight queries drain, partial results are flushed, and the process exits with code 130. Interrupted lookups are not counted as resolver failures.

<br>

### Interactive TUI

```bash
./subenum -tui
```

No flags required. Fill in the form and press `ctrl+r` to start scanning. Last-used values are saved to `~/.config/subenum/last.json` and restored on next launch. The interface is shown at the top of this README.

<br>

<details>
<summary><strong>TUI keyboard reference</strong></summary>

| Key | Action |
| :--- | :--- |
| `tab` / `shift+tab` / `↑` `↓` | Navigate fields |
| `space` | Toggle Simulate / Force |
| `ctrl+r` | Start scan |
| `ctrl+c` | Abort a running scan; quit the form or a finished scan |
| `r` | New scan - restores last-used values |
| `q` | Quit after scan completes |

</details>

<br>

---

<br>

## Tech Stack

| Layer | Components |
| :--- | :--- |
| Core Engine | Go 1.24 &middot; `net.Resolver` &middot; `context` &middot; `sync/atomic` |
| Concurrency | goroutines &middot; channels &middot; `sync.WaitGroup` &middot; `sync.Mutex` |
| TUI | Bubble Tea &middot; Bubbles (textinput, viewport, progress) &middot; Lip Gloss |
| Infrastructure | Docker &middot; distroless static nonroot &middot; Make &middot; docker-compose |
| CI/CD | GitHub Actions &middot; CodeQL &middot; Dependabot &middot; golangci-lint v2 |
| Quality | `go test -race` &middot; gosec &middot; govet &middot; staticcheck |

<br>

---

<br>

<details>
<summary><strong>Project structure</strong></summary>

<br>

```
subenum/
├── .github/
│   ├── workflows/
│   │   ├── go.yml              # CI: build, test, lint, release
│   │   ├── codeql.yml          # Weekly CodeQL security analysis
│   │   └── pages.yml           # GitHub Pages deployment
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   ├── dependabot.yml
│   └── PULL_REQUEST_TEMPLATE.md
├── data/
│   └── wordlist.txt            # Default wordlist for Docker/Make
├── docs/
│   ├── assets/
│   │   └── tui-form.png        # TUI screenshot
│   ├── ARCHITECTURE.md
│   ├── CONTRIBUTING.md
│   ├── DEVELOPER_GUIDE.md
│   ├── docker.md
│   ├── _config.yml
│   └── index.md
├── examples/
│   ├── sample_wordlist.txt
│   ├── advanced_usage.md
│   └── demo.sh
├── internal/
│   ├── dns/                    # ResolveTypes, ResolveDomainWithRetry, CheckWildcard, SimulateResolve
│   ├── output/                 # Thread-safe Writer (stdout/stderr separation)
│   ├── scan/                   # Scan engine: Config, Event types, Run()
│   ├── tui/                    # Bubble Tea UI: form, scan view, session config
│   └── wordlist/               # LoadWordlist (dedup + sanitize)
├── tools/
│   └── wordlist-gen.go
├── main.go                     # CLI entry point
├── main_test.go
├── go.mod
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── .golangci.yml               # golangci-lint v2 configuration
├── CHANGELOG.md
├── SECURITY.md
└── LICENSE                     # GNU General Public License v3.0
```

</details>

<br>

---

<br>

## Development

See [CONTRIBUTING.md](./docs/CONTRIBUTING.md) for the pull request workflow and ethical guidelines.
See [DEVELOPER_GUIDE.md](./docs/DEVELOPER_GUIDE.md) for build setup, testing, and project structure.

<br>

---

<br>

<div align="center">

[GPL-3.0 License](./LICENSE) &nbsp;&middot;&nbsp; [Security Policy](./SECURITY.md) &nbsp;&middot;&nbsp; [TM Hospitality Strategies](https://github.com/TMHSDigital)

</div>
