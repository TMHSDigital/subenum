---
layout: default
title: Developer Guide
---

# Developer Guide

This guide provides information for developers looking to contribute to or build upon the `subenum` project.

## Getting Started

### Prerequisites

To work with `subenum`, you'll need:

*   **Go Programming Language**: [Go 1.26+](https://golang.org/dl/) is required.
*   **Git**: For version control.
*   **Text Editor or IDE**: VS Code, GoLand, or any editor with Go support is recommended.

### Setting Up the Development Environment

1.  **Clone the Repository**

    ```bash
    git clone https://github.com/TMHSDigital/subenum.git
    cd subenum
    ```

2.  **Build the Project**

    To build the project, run:

    ```bash
    # Standard build (version fallback is the `Version` var in main.go)
    go build -buildvcs=false

    # Inject the git tag into the binary
    go build -buildvcs=false -ldflags "-X main.Version=$(git describe --tags --dirty)"
    ```

3.  **Run the Tool**

    To test your build, you can run:

    ```bash
    # Using a provided example wordlist
    ./subenum -w examples/sample_wordlist.txt example.com
    
    # Or with custom parameters
    ./subenum -w path/to/wordlist.txt -t 50 -timeout 2000 yourtarget.com

    # Launch the interactive TUI (no flags required)
    ./subenum -tui
    # or via Make
    make tui
    ```

## Project Structure

```
subenum/
├── .devcontainer/              # Dev container, plus a labs container (labs/devcontainer.json)
├── .github/
│   ├── workflows/
│   │   ├── go.yml              # CI: build, test, lint, govulncheck, release
│   │   ├── codeql.yml          # Weekly CodeQL security analysis
│   │   ├── devcontainer.yml    # Builds the dev container and runs checks in it
│   │   └── pages.yml           # GitHub Pages deployment
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.yml      # Structured bug report form
│   │   ├── feature_request.yml # Feature proposal form
│   │   └── config.yml          # Issue chooser settings
│   ├── scripts/                # check-links.py, release-notes.sh
│   ├── CODE_OF_CONDUCT.md      # Contributor Covenant v2.1
│   ├── CONTRIBUTING.md         # Points to docs/CONTRIBUTING.md
│   ├── FUNDING.yml
│   ├── dependabot.yml          # Automated dependency updates
│   └── PULL_REQUEST_TEMPLATE.md
├── data/
│   ├── subdomains-5k.txt       # Bundled default wordlist, embedded by data.go
│   ├── data.go
│   └── wordlist.txt            # Sample wordlist for the Docker examples (mounted at /data)
├── docs/                       # Source of the website (GitHub Pages)
│   ├── ARCHITECTURE.md         # Internals: engine, resolver, wildcard detection, subsystems
│   ├── CODE_OF_CONDUCT.md      # Community guidelines (Jekyll page)
│   ├── CONTRIBUTING.md         # PR workflow, testing, ethical guidelines
│   ├── DEVELOPER_GUIDE.md      # This file
│   ├── DOCUMENTATION_STRUCTURE.md
│   ├── ROADMAP.md              # Planned work
│   ├── docker.md               # Container setup and volume mounting
│   ├── start.md, cli.md, pipelines.md, library.md, labs.md, monitoring.md  # User guides
│   ├── _config.yml             # Jekyll config for GitHub Pages
│   ├── _data/nav.yml           # Site navigation: sidebar, footer, search, reading order
│   ├── _includes/, _layouts/, assets/  # Jekyll site templates, CSS, JS, images
│   ├── search.json             # Search index, generated at build time
│   ├── 404.html
│   └── index.html              # GitHub Pages landing page
├── examples/
│   ├── sample_wordlist.txt     # 50-entry starter wordlist
│   ├── sample_domains.txt      # Sample domain list for -dL
│   ├── advanced_usage.md       # Scripting and integration patterns
│   ├── demo.sh                 # Quick demo script
│   └── labs/                   # -simulate-zone scenarios and wordlist for docs/labs.md
├── internal/
│   ├── cliargs/                # Flags anywhere on the command line (subenum and wordlist-gen)
│   ├── ct/
│   │   ├── ct.go               # Certificate Transparency (crt.sh) client for -ct
│   │   └── ct_test.go
│   ├── diff/                   # Result comparison shared by -diff and subenum.Diff
│   ├── dns/
│   │   ├── resolver.go         # NewResolver, Lookup (ResolveTypes, Resolve, CheckWildcard,
│   │   │                       # FingerprintWildcard), Classify, ParseTypes
│   │   ├── transport.go        # UDP (TCP fallback), DNS over TLS, DNS over HTTPS dialers
│   │   ├── axfr.go             # Transfer: AXFR zone transfer over TCP (-axfr)
│   │   ├── nsec.go             # ProbeDenial: is the zone NSEC-walkable (-axfr)
│   │   ├── pool.go             # Pool: the -r resolver pool (benching, canaries, second opinions)
│   │   ├── ratelimit.go        # RateLimiter, WithLimiter (per-wire-query pacing)
│   │   ├── takeover.go         # TakeoverProvider, TakeoverHint (dangling CNAMEs and NS delegations)
│   │   ├── scope.go            # AddressScope, InternalScope: non-public address scopes
│   │   ├── simulate.go         # Simulation.Resolve (seeded synthetic DNS)
│   │   ├── testdns_test.go     # Table-driven wrapper over internal/dnstest
│   │   └── *_test.go           # Resolver, transport, pool, rate, takeover, simulation tests
│   ├── dnsserver/              # Scriptable loopback DNS server (UDP, TCP, DoT, DoH)
│   ├── dnstest/                # dnsserver for tests: stops on cleanup, fails the test on error
│   ├── labzone/                # -simulate-zone scenario parser and answer logic
│   ├── mcp/                    # MCP server over stdio (JSON-RPC, tools only) for subenum mcp
│   ├── output/
│   │   ├── writer.go           # Thread-safe output (results→stdout, rest→stderr)
│   │   ├── file.go             # File: atomically replaced -o results file
│   │   ├── summary.go          # Run-quality summary: JSONL summary line, -stats file
│   │   ├── sarif.go            # -sarif: takeover candidates as SARIF 2.1.0
│   │   ├── eta.go              # Progress ETA estimate
│   │   ├── log.go              # -log-format: text or JSON diagnostics on stderr
│   │   └── *_test.go           # Writer, file, ETA tests
│   ├── passive/                # -sources: Source interface, registry, Wayback Machine source
│   ├── permute/                # -permute candidate generation
│   ├── report/                 # Run-quality report built from finished scans
│   ├── scan/
│   │   ├── options.go          # Options: settings shared by CLI and TUI (Validate, Config)
│   │   ├── runner.go           # Scan engine: Config, Event/NoticeKind, Stats, Run
│   │   ├── dispatcher.go       # Lazy candidate generation in chunks, budgets, resume watermark
│   │   ├── autorate.go         # -auto-rate back-off controller
│   │   ├── scope.go            # -exclude patterns (ValidateExcludes, IsExcluded)
│   │   ├── settings.go         # Setting tokens in engine messages, rendered per front end
│   │   ├── verdict.go          # Run-quality verdicts: complete, degraded, unreliable
│   │   ├── verify.go           # Verify: re-check names on the trusted resolver (-diff)
│   │   └── *_test.go           # Dispatcher, recursion, rate, wildcard, pool, resume, cancellation tests
│   ├── tui/
│   │   ├── model.go            # Root Bubble Tea model (form → scan state machine)
│   │   ├── form.go             # Config form screen (textinput fields + toggles)
│   │   ├── scan_view.go        # Live results screen (viewport + progress bar)
│   │   ├── logo.go             # Styled wordmark
│   │   ├── config.go           # Session persistence: load/save <user config dir>/subenum/last.json
│   │   └── *_test.go           # Model, form, scan view and config tests
│   ├── validate/
│   │   ├── validate.go         # DNSServer, Domain, NormalizeDomain, DefaultDNSServer
│   │   ├── punycode.go         # IDN → punycode (A-label) conversion
│   │   └── *_test.go           # Validator and punycode tests
│   └── wordlist/
│       ├── reader.go           # ReadLines, ReadLinesFrom, Normalize, Build, Prepare/For, LoadWordlist
│       └── *_test.go           # Wordlist reading, normalization and dedup tests
├── pkg/
│   └── subenum/                # Public Go library API: Config, Scan, Run, Event, Stats
├── tools/
│   ├── wordlist-gen.go         # Custom wordlist generator utility
│   ├── wordlist-gen_test.go    # Generator tests
│   └── README.md               # Wordlist generator docs
├── .gitattributes              # Line-ending normalization rules
├── .gitignore
├── .golangci.yml               # Linter configuration (golangci-lint v2)
├── .goreleaser.yaml            # Release archives, completions, man page
├── main.go                     # CLI entry point: run, flag parsing and validation, exit codes
├── main_session.go             # runWith and the per-run session: the -dL target loop
├── main_completion.go          # completion and man subcommands
├── main_config.go              # Config file and SUBENUM_* environment defaults, -print-config
├── main_ct.go                  # -ct / -sources: passive source names as candidates
├── main_axfr.go                # -axfr: zone transfer names as candidates
├── main_diff.go                # -diff / -diff-records against a previous results file
├── main_dryrun.go              # -dry-run: the scan plan and its cost, no queries sent
├── main_lab.go                 # -simulate-zone: serve a lab scenario locally
├── main_mcp.go                 # subenum mcp: MCP tools, allow-list and caps
├── main_permute.go             # -permute / -seeds: the permutation pass
├── main_resume.go              # -resume / -state: save and replay an interrupted run
├── main_summary.go             # Run-quality report assembly (-stats, JSONL summary line)
├── main_wordlist.go            # -w file or the bundled wordlist
├── main_test.go                # CLI-level tests: validation, flag logic
├── main_e2e_test.go            # End-to-end runWith tests: -dL, stdin, formats, exit codes
├── main_docs_test.go           # Doc checks: README and site flag tables cover the CLI
├── main_signal_unix_test.go    # SIGTERM exit code test (Unix only)
├── main_*_test.go              # Config, CT, diff, exit, lab and resume tests
├── action.yml                  # GitHub Action
├── CITATION.cff                # Citation metadata
├── go.mod / go.sum             # Go module (Bubble Tea TUI is linked into every binary)
├── Dockerfile                  # Multi-stage distroless static nonroot build
├── docker-compose.yml          # Compose orchestration
├── Makefile                    # Build, test, lint, simulate, Docker targets
├── CHANGELOG.md                # Versioned release history
├── README.md                   # Project overview
├── SECURITY.md                 # Vulnerability disclosure policy
└── LICENSE                     # GNU General Public License v3.0
```

## Running Tests

To run all tests:

```bash
go test -v -race ./...
```

On Windows, use Go 1.26.3 or later for race runs. Go 1.26.0 reports false
data races there (between `context.WithTimeout` and the net package's DNS
lookup goroutine) and can crash with `Exception 0xc0000005` in `scan.Run`;
neither is a bug in subenum, and Linux, where CI runs `-race`, is not
affected. `go.mod` keeps `go 1.26.0` as the minimum, so pick the toolchain
per command:

```bash
GOTOOLCHAIN=go1.26.3 go test -race ./...
```

In PowerShell:

```powershell
$env:GOTOOLCHAIN = "go1.26.3"; go test -race ./...; Remove-Item Env:GOTOOLCHAIN
```

Default `go test ./...` is hermetic (in-process DNS responder, no outbound
network). The optional live resolver smoke test is gated on an env var:

```bash
# Unix
SUBENUM_NETWORK_TESTS=1 go test ./internal/dns -run TestLiveResolverSmoke

# PowerShell
$env:SUBENUM_NETWORK_TESTS = "1"
go test ./internal/dns -run TestLiveResolverSmoke
```

### Writing Tests

When adding new features or modifying existing ones, please ensure you add appropriate tests. Tests must not depend on the network: DNS tests in `internal/dns` use `startTestDNS` (in `testdns_test.go`), a table-driven wrapper over `internal/dnstest`, the shared in-process UDP/TCP DNS server; names missing from the table get NXDOMAIN and missing record types get NODATA. Use `dnstest.Start` directly when a test needs per-query scripting or exact query counts (`QueriesFor`). The `startTestDNS` server's `Resolver` method returns a `*net.Resolver` pointed at it. Here's a basic structure (save it as a `_test.go` file in `internal/dns`):

```go
package dns

import (
	"context"
	"testing"
	"time"
)

func TestGuideResolveOutcomes(t *testing.T) {
	// In-process DNS server: no outbound network. Names missing from the
	// table get NXDOMAIN.
	srv := startTestDNS(t, map[string]testReply{
		"www.example.com":  {A: "192.0.2.1"},
		"busy.example.com": {Refused: true},
	})
	timeout := time.Second
	r := srv.Resolver(timeout)

	testCases := []struct {
		name   string
		domain string
		want   Outcome
	}{
		{"resolves", "www.example.com", OutcomeFound},
		{"does not exist", "missing.example.com", OutcomeNXDomain},
		{"server refuses", "busy.example.com", OutcomeRefused},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, got := Lookup{Resolver: r, Timeout: timeout, Attempts: 1, Types: []string{"A"}}.Resolve(context.Background(), tc.domain)
			if got != tc.want {
				t.Errorf("%s: outcome = %v, want %v", tc.domain, got, tc.want)
			}
		})
	}
}
```

Scan-engine tests in `internal/scan` can avoid DNS entirely by setting the unexported `resolveHook` field of `scan.Config`, or by running with `Simulate` set; see `runner_test.go`.

## Debugging Tips

### Common Issues

1.  **DNS Resolution Timeouts**: If DNS lookups seem to hang or time out frequently:
    *   Verify your internet connection.
    *   Try increasing the timeout value.
    *   Consider using a different DNS server.

2.  **Performance Issues with Large Wordlists**:
    *   Adjust the concurrency level (`-t` flag) based on your system's capabilities.
    *   For very large wordlists, consider splitting them into smaller files and running separate instances of the tool.

### Debugging with Go Tools

Go provides several tools for debugging:

*   **Print statements**: Simple but effective. Add `fmt.Printf()` statements to trace execution.
*   **Delve**: A dedicated debugger for Go. Install with `go install github.com/go-delve/delve/cmd/dlv@latest`.
*   **Race detector**: Run with `go build -race` to detect race conditions when testing concurrent code.

## Making Changes

### Coding Style

Please follow these style guidelines when contributing:

*   Adhere to the [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments) standards.
*   Run `gofmt` before committing to ensure consistent code style.
*   Use meaningful variable and function names.
*   Add comments for public functions and complex logic.

### Git Workflow

1.  **Create a Branch**:
    ```bash
    git checkout -b feature/your-feature-name
    ```

2.  **Make Changes and Commit**:
    ```bash
    git add .
    git commit -m "Add feature: brief description"
    ```

3.  **Push and Create Pull Request**:
    ```bash
    git push origin feature/your-feature-name
    ```
    Then create a pull request on GitHub.

## Dependencies Management

`subenum` aims to minimize external dependencies, relying primarily on the Go standard library.

There is no CLI-only build: `main` imports `internal/tui`, so Bubble Tea links
into every binary. Direct third-party deps:

- [`charm.land/bubbletea/v2`](https://github.com/charmbracelet/bubbletea) - Elm-architecture terminal UI framework
- [`charm.land/bubbles/v2`](https://github.com/charmbracelet/bubbles) - reusable TUI components (textinput, viewport, progress bar)
- [`charm.land/lipgloss/v2`](https://github.com/charmbracelet/lipgloss) - terminal styling

Keep these on versions whose `go` directive is at most the module's `go
1.26.0`: lipgloss v2.1.0 needs Go 1.26.7, so lipgloss stays on v2.0.x for now.

If you need to add a further dependency:

1.  Evaluate whether it's truly necessary or if the functionality can be implemented using the standard library.
2.  If a dependency is needed, add it with:
    ```bash
    go get github.com/example/dependency
    ```
3.  Run `go mod tidy` to update the `go.mod` and `go.sum` files.

## Working on the Website

The site at [tmhsdigital.github.io/subenum](https://tmhsdigital.github.io/subenum/) is built from `docs/` by the stock GitHub Pages Jekyll action (`.github/workflows/pages.yml`), with no theme and no JavaScript dependencies.

- `docs/index.html` is the landing page; every other page is Markdown with `layout: default`, which adds the sidebar, the on-page contents and the previous/next links.
- `docs/_data/nav.yml` is the single list of pages and sections. Add a new page there or it won't appear in the sidebar, the footer or search.
- `docs/search.json` is generated at build time from the pages in `nav.yml`; `docs/assets/js/site.js` runs search, tabs, copy buttons and the hero animation.
- The palette lives at the top of `docs/assets/css/site.css`. The outcome colours (resolved, nxdomain, timeout, refused) mean the same thing everywhere, so reuse the tokens rather than adding colours.
- The site deploys from `main`, so it can document a feature before a release has it. List such a subcommand, flag, Action input or output, or library identifier in `docs/_data/unreleased.yml`, run `make docs-flags`, and put `{% raw %}{% include unreleased.html flag="name" %}{% endraw %}` (or `command=` / `action=` / `library=`) after it in prose; the site then tags it "unreleased". In the release commit, empty those lists, run `make docs-flags` again, and remove the README's "Unreleased" notes (the README is not rendered by the site, so it says so in plain text).

To preview locally, build with the same image the workflow uses and serve the output:

```bash
docker run --rm -w /src -v "$PWD/docs:/src/docs:ro" -v "$PWD/docs/_preview/site:/src/_site" \
  -e INPUT_SOURCE=./docs -e INPUT_DESTINATION=./_site -e INPUT_TOKEN="$(gh auth token)" \
  -e GITHUB_WORKSPACE=/src -e GITHUB_REPOSITORY=TMHSDigital/subenum -e PAGES_REPO_NWO=TMHSDigital/subenum \
  ghcr.io/actions/jekyll-build-pages:v1.0.13
mkdir -p /tmp/subenum-site && rm -rf /tmp/subenum-site/subenum && cp -r docs/_preview/site /tmp/subenum-site/subenum
python3 -m http.server 4000 -d /tmp/subenum-site   # http://localhost:4000/subenum/
```

The token is needed because the header shows the latest release tag. `docs/_preview/` is gitignored.

## Already Shipped

The following capabilities are implemented and available today:

*   **Terminal UI** (`-tui`): a Bubble Tea form-based config screen and live-scrolling results view, no arguments required to launch. Last-used values persist across sessions in `last.json` in the user config directory (`~/.config/subenum/` on Linux, `~/Library/Application Support/subenum/` on macOS, `%AppData%\subenum\` on Windows).
*   **Output Formats** (`-format text|json|jsonl|csv`): on stdout and in the atomically replaced output file (`-o`); `jsonl` streams one object per line.
*   **Record Types** (`-type A,AAAA,CNAME,NS,MX,TXT`): per-type lookups filtered to the requested types.
*   **Recursive Enumeration** (`-recursive` with `-depth`): enumerate subdomains of discovered subdomains, with loop and duplicate protection and per-branch wildcard checks.
*   **Rate Limiting** (`-rate`): cap DNS queries per second on the wire across the worker pool, counting every record type, retry and wildcard probe.
*   **Multiple Targets** (`-dL`): scan a list of apex domains, each as an independent scan, with exit code 3 when only some targets fail.

## Future Development

See `docs/ROADMAP.md` for the next-pass list. Areas still open:

*   **Additional record types**: `Lookup.ResolveTypes` covers A, AAAA, CNAME, NS, MX and TXT; a new type is a case in `lookupType`, an entry in `supportedTypes` and `queriesPerType`, and (to test it) an answer builder in `internal/dnsserver` and a record type in `internal/labzone`.

When working on new features, please update the documentation accordingly and add tests to cover the new functionality. 