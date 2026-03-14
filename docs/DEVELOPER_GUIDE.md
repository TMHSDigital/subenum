---
layout: default
title: Developer Guide
---

# Developer Guide

This guide provides information for developers looking to contribute to or build upon the `subenum` project.

## Getting Started

### Prerequisites

To work with `subenum`, you'll need:

*   **Go Programming Language**: [Go 1.22+](https://golang.org/dl/) is required.
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
    # Standard build
    go build
    
    # If encountering VCS issues
    go build -buildvcs=false
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
│   ├── docker.md               # Container setup and volume mounting
│   ├── _config.yml             # Jekyll config for GitHub Pages
│   └── index.md                # GitHub Pages landing page
├── examples/
│   ├── sample_wordlist.txt     # 50-entry starter wordlist
│   ├── sample_domains.txt      # Sample domain list
│   ├── advanced_usage.md       # Scripting and integration patterns
│   ├── demo.sh                 # Quick demo script
│   └── multi_domain_scan.sh    # Batch scanning example
├── internal/
│   ├── dns/
│   │   ├── resolver.go         # ResolveDomain, ResolveDomainWithRetry, CheckWildcard
│   │   ├── resolver_test.go    # DNS resolution and wildcard detection tests
│   │   ├── simulate.go         # SimulateResolution (synthetic DNS)
│   │   └── simulate_test.go    # Simulation logic tests
│   ├── output/
│   │   ├── writer.go           # Thread-safe output (results→stdout, rest→stderr)
│   │   └── writer_test.go      # Output writer tests
│   ├── scan/
│   │   └── runner.go           # Scan engine: Config, Event types, Run(ctx, cfg, events)
│   ├── tui/
│   │   ├── model.go            # Root Bubble Tea model (form → scan state machine)
│   │   ├── form.go             # Config form screen (textinput fields + toggles)
│   │   ├── scan_view.go        # Live results screen (viewport + progress bar)
│   │   └── config.go           # Session persistence: load/save ~/.config/subenum/last.json
│   └── wordlist/
│       ├── reader.go           # LoadWordlist (dedup + sanitize)
│       └── reader_test.go      # Wordlist loading and dedup tests
├── tools/
│   ├── wordlist-gen.go         # Custom wordlist generator utility
│   └── README.md               # Wordlist generator docs
├── .gitattributes              # Line-ending normalization rules
├── .golangci.yml               # Linter configuration (golangci-lint v2)
├── main.go                     # CLI entry point: flag parsing, wiring
├── main_test.go                # CLI-level tests: validation, flag logic
├── go.mod                      # Go module (Bubble Tea for TUI; zero deps in CLI-only builds)
├── Dockerfile                  # Multi-stage Alpine build
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

To run only fast, offline tests (skips network-dependent tests):

```bash
go test -v -short ./...
```

### Writing Tests

When adding new features or modifying existing ones, please ensure you add appropriate tests. Here's a basic structure for tests:

```go
package dns_test

import (
    "context"
    "testing"
    "time"

    "github.com/TMHSDigital/subenum/internal/dns"
)

func TestResolveDomain(t *testing.T) {
    testCases := []struct {
        name     string
        domain   string
        timeout  time.Duration
        expected bool
    }{
        {
            name:     "Valid domain",
            domain:   "google.com",
            timeout:  time.Second,
            expected: true,
        },
        {
            name:     "Invalid domain",
            domain:   "thisdoesnotexisthopefully.com",
            timeout:  time.Second,
            expected: false,
        },
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            result := dns.ResolveDomain(context.Background(), tc.domain, tc.timeout, "8.8.8.8:53", false)
            if result != tc.expected {
                t.Errorf("Expected %v for domain %s, got %v", tc.expected, tc.domain, result)
            }
        })
    }
}
```

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

The CLI path (`run()`) has zero external dependencies. The TUI path (`-tui` flag) adds:

- [`github.com/charmbracelet/bubbletea`](https://github.com/charmbracelet/bubbletea) — Elm-architecture terminal UI framework
- [`github.com/charmbracelet/bubbles`](https://github.com/charmbracelet/bubbles) — reusable TUI components (textinput, viewport, progress bar)

If you need to add a further dependency:

1.  Evaluate whether it's truly necessary or if the functionality can be implemented using the standard library.
2.  If a dependency is needed, add it with:
    ```bash
    go get github.com/example/dependency
    ```
3.  Run `go mod tidy` to update the `go.mod` and `go.sum` files.

## Future Development

Areas for potential enhancement include:

*   **Terminal UI**: An interactive TUI (`-tui` flag) built with Bubble Tea. Provides a form-based config screen and a live-scrolling results view — no arguments required to launch. Last-used values persist to `~/.config/subenum/last.json` across sessions.
*   **Output Formats**: Supporting different output formats (JSON, CSV) in addition to the current plain text output file (`-o`).
*   **Result Filtering**: Allowing users to filter results based on DNS record types.
*   **Recursive Enumeration**: Adding support for recursive subdomain enumeration (e.g., finding subdomains of discovered subdomains).
*   **Rate Limiting**: Adding configurable rate limiting for DNS queries to avoid triggering abuse detection.

When working on new features, please update the documentation accordingly and add tests to cover the new functionality. 