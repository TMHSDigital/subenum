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
    ```

## Project Structure

```
subenum/
├── main.go                 # Main application code
├── main_test.go            # Test suite
├── go.mod                  # Go module definition
├── Makefile                # Build, test, lint, Docker targets
├── Dockerfile              # Multi-stage Docker build
├── docker-compose.yml      # Docker Compose config
├── .golangci.yml           # Linter configuration
├── README.md               # Project overview
├── LICENSE                 # License information
├── SECURITY.md             # Security policy and disclosure
├── .github/
│   ├── workflows/
│   │   ├── go.yml          # CI: build, test, lint, release
│   │   ├── pages.yml       # GitHub Pages deployment
│   │   └── codeql.yml      # CodeQL security scanning
│   ├── dependabot.yml      # Automated dependency updates
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── ISSUE_TEMPLATE/     # Bug report & feature request templates
├── docs/                   # Documentation (served via GitHub Pages)
│   ├── _config.yml         # Jekyll site configuration
│   ├── index.md            # Site home page
│   ├── ARCHITECTURE.md     # Architectural details
│   ├── DEVELOPER_GUIDE.md  # This file
│   ├── CODE_OF_CONDUCT.md  # Community guidelines
│   ├── CONTRIBUTING.md     # Contribution guidelines
│   └── docker.md           # Docker usage guide
├── data/
│   └── wordlist.txt        # Default wordlist
├── examples/               # Example files and usage demos
│   ├── sample_wordlist.txt # Sample subdomain prefixes
│   ├── sample_domains.txt  # Sample domain list
│   └── advanced_usage.md   # Advanced usage examples
├── tools/
│   ├── wordlist-gen.go     # Wordlist generator utility
│   └── README.md           # Wordlist generator docs
└── logs/
    └── CHANGELOG.md        # Project change history
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
package main

import (
    "context"
    "testing"
    "time"
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
            result := resolveDomain(context.Background(), tc.domain, tc.timeout, DefaultDNSServer, false)
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

`subenum` aims to minimize external dependencies, relying primarily on the Go standard library. If you need to add a dependency:

1.  Evaluate whether it's truly necessary or if the functionality can be implemented using the standard library.
2.  If a dependency is needed, add it with:
    ```bash
    go get github.com/example/dependency
    ```
3.  Run `go mod tidy` to update the `go.mod` and `go.sum` files.

## Future Development

Areas for potential enhancement include:

*   **Output Formats**: Supporting different output formats (JSON, CSV) in addition to the current plain text output file (`-o`).
*   **Result Filtering**: Allowing users to filter results based on DNS record types.
*   **Recursive Enumeration**: Adding support for recursive subdomain enumeration (e.g., finding subdomains of discovered subdomains).
*   **Wildcard Detection**: Detecting wildcard DNS records that resolve all subdomains.
*   **Rate Limiting**: Adding configurable rate limiting for DNS queries to avoid triggering abuse detection.

When working on new features, please update the documentation accordingly and add tests to cover the new functionality. 