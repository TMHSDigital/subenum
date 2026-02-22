# subenum

[![Build](https://img.shields.io/github/actions/workflow/status/TMHSDigital/subenum/go.yml?branch=main&label=build)](https://github.com/TMHSDigital/subenum/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/TMHSDigital/subenum)](https://goreportcard.com/report/github.com/TMHSDigital/subenum)
[![Release](https://img.shields.io/github/v/release/TMHSDigital/subenum)](https://github.com/TMHSDigital/subenum/releases)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-supported-0db7ed)](docs/docker.md)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/TMHSDigital/subenum/codeql.yml?label=CodeQL)](https://github.com/TMHSDigital/subenum/actions/workflows/codeql.yml)

**Fast, concurrent subdomain enumeration via DNS resolution. Written in Go.**

Built for security professionals and students conducting authorized reconnaissance. Uses a configurable worker pool to fire hundreds of DNS queries in parallel, with graceful shutdown, retry logic, and safe simulation mode built in.

> **For authorized use only.** Only scan domains you own or have explicit written permission to test.

---

## How It Works

```
wordlist.txt  ──►  worker pool (N goroutines)  ──►  DNS resolver  ──►  stdout / file
                        │                               │
                   ctx cancellation              timeout + retries
                   (SIGINT/SIGTERM)              per query
```

Each wordlist entry is combined with the target domain (`api` + `example.com` → `api.example.com`) and resolved concurrently. Only entries that return a DNS record are reported.

---

## Installation

**From source** (requires Go 1.22+):

```bash
git clone https://github.com/TMHSDigital/subenum.git
cd subenum
go build -buildvcs=false -o subenum
```

**From a release binary:**

Download a pre-built binary for your platform from the [Releases](https://github.com/TMHSDigital/subenum/releases) page.

**Docker:**

```bash
docker build -t subenum .
docker run --rm -v $(pwd)/data:/data subenum -w /data/wordlist.txt example.com
```

**Make:**

```bash
make build     # compile
make run       # build and run with defaults
make help      # list all targets
```

---

## Usage

```
subenum -w <wordlist> [flags] <domain>
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-w <file>` | — | Wordlist file, one prefix per line **(required)** |
| `-t <n>` | `100` | Number of concurrent worker goroutines |
| `-timeout <ms>` | `1000` | Per-query DNS timeout in milliseconds |
| `-dns-server <ip:port>` | `8.8.8.8:53` | DNS server (IP and port validated on startup) |
| `-retries <n>` | `1` | Retry attempts per subdomain on failure |
| `-o <file>` | — | Write results to file in addition to stdout |
| `-v` | `false` | Verbose output — IPs, timings, per-query status |
| `-progress` | `true` | Live progress line (disable with `-progress=false`) |
| `-simulate` | `false` | Simulation mode — no real DNS queries |
| `-hit-rate <n>` | `15` | Simulated resolution rate, percent (1–100) |
| `-version` | — | Print version and exit |

---

## Examples

**Basic scan:**

```bash
./subenum -w wordlist.txt example.com
```

```
Found: api.example.com
Found: mail.example.com
Found: www.example.com
```

**High-throughput scan with Cloudflare DNS, saving results:**

```bash
./subenum -w wordlist.txt -t 300 -timeout 500 -dns-server 1.1.1.1:53 -o results.txt example.com
```

**Verbose scan — shows IPs, timings, and a final summary:**

```bash
./subenum -w wordlist.txt -v example.com
```

```
Starting subenum v0.3.0
Mode: LIVE DNS RESOLUTION
Target domain: example.com
Wordlist: wordlist.txt
Concurrency: 100 workers
Timeout: 1000 ms
Retries: 1
DNS Server: 8.8.8.8:53
---
Total wordlist entries: 1842
Resolved: api.example.com (IP: 93.184.216.34) in 28ms
Found: api.example.com
Resolved: mail.example.com (IP: 93.184.216.35) in 31ms
Found: mail.example.com
Progress: 100.0% (1842/1842) | Found: 7

Scan completed for example.com
Processed 1842 subdomain prefixes
Found 7 subdomains
```

**Resilient scan for flaky networks:**

```bash
./subenum -w wordlist.txt -retries 3 -timeout 2000 example.com
```

**Clean output for piping into other tools:**

```bash
./subenum -w wordlist.txt -progress=false example.com \
  | cut -d' ' -f2 \
  | your-takeover-scanner
```

**Stop mid-scan cleanly** — press `Ctrl+C`. In-flight queries drain, partial results are printed, and the output file is flushed.

---

## Simulation Mode

Run without making any real DNS queries. Useful for demonstrations, CI pipelines, and feature development.

```bash
./subenum -simulate -hit-rate 20 -w examples/sample_wordlist.txt example.com
```

```
╔════════════════════════════════════════════════════════════════════╗
║  SIMULATION MODE ACTIVE - NO ACTUAL DNS QUERIES WILL BE PERFORMED  ║
║  Results are artificially generated for educational purposes only  ║
╚════════════════════════════════════════════════════════════════════╝

Found (SIMULATED): api.example.com
Found (SIMULATED): dev.example.com
Found (SIMULATED): staging.example.com
```

Common subdomains (`www`, `api`, `mail`, `dev`, `staging`, etc.) resolve at a fixed 90% rate. All other entries use the `-hit-rate` percentage.

---

## Why Subdomain Enumeration

Subdomain enumeration is a standard first step in authorized penetration testing and security assessments. Discovered subdomains can surface:

- Forgotten or unmaintained services running outdated software
- Development and staging environments with weaker security controls
- Infrastructure not covered by WAFs or other perimeter defenses
- Services leaking internal naming conventions and technology choices

This tool exists to help security professionals map that attack surface efficiently — on domains they are authorized to test.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Architecture](docs/ARCHITECTURE.md) | Internals: worker pool, context propagation, output pipeline |
| [Developer Guide](docs/DEVELOPER_GUIDE.md) | Building, testing, project structure, contribution workflow |
| [Contributing](docs/CONTRIBUTING.md) | How to report bugs, suggest features, and submit PRs |
| [Docker Usage](docs/docker.md) | Container setup, volume mounting, simulation in Docker |
| [Advanced Usage](examples/advanced_usage.md) | Scripting, integration, combined flag examples |
| [Changelog](logs/CHANGELOG.md) | Release history |

---

## Legal

This software is provided for **educational and authorized security testing purposes only**.

- You must have explicit written permission to scan any domain you do not own.
- Do not use this tool for unauthorized access, data collection, or disruption of services.
- Users are solely responsible for compliance with all applicable laws.

This software is licensed under the GNU General Public License v3.0. See [LICENSE](LICENSE) for full terms. Derivatives must also be distributed under GPL-3.0.

---

## Contributing

Pull requests are welcome. See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for the workflow, testing requirements, and ethical guidelines.
