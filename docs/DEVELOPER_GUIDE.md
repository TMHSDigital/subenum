---
layout: default
title: Developer Guide
---

# Developer Guide

This guide provides information for developers looking to contribute to or build upon the `subenum` project.

## Getting Started

### Prerequisites

To work with `subenum`, you'll need:

*   **Go Programming Language**: [Go 1.24+](https://golang.org/dl/) is required.
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
├── .github/
│   ├── workflows/
│   │   ├── go.yml              # CI: build, test, lint, release
│   │   ├── codeql.yml          # Weekly CodeQL security analysis
│   │   └── pages.yml           # GitHub Pages deployment
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md       # Structured bug report form
│   │   └── feature_request.md  # Feature proposal template
│   ├── CODE_OF_CONDUCT.md      # Contributor Covenant v2.1
│   ├── CONTRIBUTING.md         # Points to docs/CONTRIBUTING.md
│   ├── dependabot.yml          # Automated dependency updates
│   └── PULL_REQUEST_TEMPLATE.md
├── data/
│   └── wordlist.txt            # Default wordlist for Docker/Make
├── docs/
│   ├── ARCHITECTURE.md         # Internals: worker pool, context, output
│   ├── CODE_OF_CONDUCT.md      # Community guidelines (Jekyll page)
│   ├── CONTRIBUTING.md         # PR workflow, testing, ethical guidelines
│   ├── DEVELOPER_GUIDE.md      # This file
│   ├── DOCUMENTATION_STRUCTURE.md
│   ├── ROADMAP.md              # Planned work
│   ├── docker.md               # Container setup and volume mounting
│   ├── _config.yml             # Jekyll config for GitHub Pages
│   ├── _includes/, _layouts/, assets/  # Jekyll site templates, CSS, images
│   └── index.md                # GitHub Pages landing page
├── examples/
│   ├── sample_wordlist.txt     # 50-entry starter wordlist
│   ├── sample_domains.txt      # Sample domain list for -dL
│   ├── advanced_usage.md       # Scripting and integration patterns
│   └── demo.sh                 # Quick demo script
├── internal/
│   ├── dns/
│   │   ├── resolver.go         # NewResolver, ResolveTypes, ResolveDomainWithRetry, Classify,
│   │   │                       # CheckWildcard, FingerprintWildcard, ParseTypes
│   │   ├── resolver_test.go    # DNS resolution, classification and wildcard detection tests
│   │   ├── ratelimit.go        # RateLimiter, WithLimiter (per-wire-query pacing)
│   │   ├── ratelimit_test.go   # Rate limiter tests
│   │   ├── testdns_test.go     # In-process UDP/TCP DNS responder for hermetic tests
│   │   ├── simulate.go         # SimulateResolve (seeded synthetic DNS)
│   │   └── simulate_test.go    # Simulation logic tests
│   ├── output/
│   │   ├── writer.go           # Thread-safe output (results→stdout, rest→stderr)
│   │   ├── file.go             # File: atomically replaced -o results file
│   │   └── writer_test.go      # Output writer tests
│   ├── scan/
│   │   ├── options.go          # Options: settings shared by CLI and TUI (Validate, Config)
│   │   ├── options_test.go     # Options validation tests
│   │   ├── runner.go           # Scan engine: Config, Event/NoticeKind, Stats, Run
│   │   └── runner_test.go      # Dispatcher lifecycle, recursion, rate, wildcard, cancellation tests
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
│       ├── reader.go           # ReadLines, Normalize, Build, LoadWordlist
│       └── reader_test.go      # Wordlist reading, normalization and dedup tests
├── tools/
│   ├── wordlist-gen.go         # Custom wordlist generator utility
│   ├── wordlist-gen_test.go    # Generator tests
│   └── README.md               # Wordlist generator docs
├── .gitattributes              # Line-ending normalization rules
├── .gitignore
├── .golangci.yml               # Linter configuration (golangci-lint v2)
├── main.go                     # CLI entry point: flag parsing, -dL loop, exit codes
├── main_test.go                # CLI-level tests: validation, flag logic
├── main_e2e_test.go            # End-to-end run() tests: -dL, stdin, formats, exit codes
├── main_signal_unix_test.go    # SIGTERM exit code test (Unix only)
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

When adding new features or modifying existing ones, please ensure you add appropriate tests. Tests must not depend on the network: DNS tests in `internal/dns` use `startTestDNS` (in `testdns_test.go`), an in-process UDP/TCP server that answers from a table of `testReply` entries; names missing from the table get NXDOMAIN. Its `Resolver` method returns a `*net.Resolver` pointed at it. Here's a basic structure (save it as a `_test.go` file in `internal/dns`):

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
			_, got := ResolveDomainWithRetry(context.Background(), r, tc.domain, timeout, nil, 1, []string{"A"})
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

- [`github.com/charmbracelet/bubbletea`](https://github.com/charmbracelet/bubbletea) - Elm-architecture terminal UI framework
- [`github.com/charmbracelet/bubbles`](https://github.com/charmbracelet/bubbles) - reusable TUI components (textinput, viewport, progress bar)
- [`github.com/charmbracelet/lipgloss`](https://github.com/charmbracelet/lipgloss) - terminal styling

If you need to add a further dependency:

1.  Evaluate whether it's truly necessary or if the functionality can be implemented using the standard library.
2.  If a dependency is needed, add it with:
    ```bash
    go get github.com/example/dependency
    ```
3.  Run `go mod tidy` to update the `go.mod` and `go.sum` files.

## Already Shipped

The following capabilities are implemented and available today:

*   **Terminal UI** (`-tui`): a Bubble Tea form-based config screen and live-scrolling results view, no arguments required to launch. Last-used values persist to `~/.config/subenum/last.json` across sessions.
*   **Output Formats** (`-format text|json|jsonl|csv`): on stdout and in the atomically replaced output file (`-o`); `jsonl` streams one object per line.
*   **Record Types** (`-type A,AAAA,CNAME`): per-type lookups filtered to the requested types.
*   **Recursive Enumeration** (`-recursive` with `-depth`): enumerate subdomains of discovered subdomains, with loop and duplicate protection and per-branch wildcard checks.
*   **Rate Limiting** (`-rate`): cap DNS queries per second on the wire across the worker pool, counting every record type, retry and wildcard probe.
*   **Multiple Targets** (`-dL`): scan a list of apex domains, each as an independent scan, with exit code 3 when only some targets fail.

## Future Development

See `docs/ROADMAP.md` for the next-pass list. Areas still open:

*   **Additional record types**: extend `dns.ResolveTypes` beyond A/AAAA/CNAME (for example MX, TXT, NS).

When working on new features, please update the documentation accordingly and add tests to cover the new functionality. 