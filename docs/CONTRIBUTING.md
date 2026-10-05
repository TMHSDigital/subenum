---
layout: default
title: Contributing
---

# Contributing to subenum

We welcome contributions! Please read this guide to understand how you can contribute.

See the [Code of Conduct](CODE_OF_CONDUCT.html).

## Development Environment Setup

### Prerequisites

- Go 1.26 or later
- Git
- Make (optional but recommended)
- Docker (optional, for containerized development)

The `go` directive in `go.mod` must stay exactly `go 1.26.0`. CI fails the build
if it drifts. Current `golang.org/x/sys` and `golang.org/x/text` declare
`go 1.26.0`, so it is also the floor. New dependencies must keep it and pass
`govulncheck`, which CI runs. On PowerShell, quote `-go=1.26.0`; unquoted it is
parsed as `-go=1`. After changing dependencies run `make tidy`.

### Codespaces / Dev Containers

The quickest start needs no local setup. [Open the repository in GitHub Codespaces](https://codespaces.new/TMHSDigital/subenum), or use "Reopen in Container" in VS Code. The container in `.devcontainer/` comes with Go 1.26 and the CI version of golangci-lint, and builds the binary. `make test` and `./subenum -simulate example.com` then work with no network access to any target.

New here? Look for issues labeled [`good first issue`](https://github.com/TMHSDigital/subenum/labels/good%20first%20issue), and ask questions in [Discussions](https://github.com/TMHSDigital/subenum/discussions).

### Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork**:
   ```bash
   git clone https://github.com/YOUR-USERNAME/subenum.git
   cd subenum
   ```
3. **Set up the upstream remote**:
   ```bash
   git remote add upstream https://github.com/TMHSDigital/subenum.git
   ```

## Development Workflow

### Using Make

The project includes a Makefile to simplify development tasks:

```bash
# Build the binary
make build

# Run tests
make test

# Run linter
make lint

# Tidy modules (keeps the go 1.26.0 pin)
make tidy

# Clean up build artifacts
make clean

# Run a safe simulated scan (live scans need: make run DOMAIN=yourdomain.com)
make simulate
```

### Using Docker

You can use Docker for development to ensure a consistent environment:

```bash
# Build the Docker image
make docker-build

# Run the tool in a Docker container
make docker-run
```

## Pull Request Process

1. **Create a branch** for your feature:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** and ensure they follow the project's coding standards

3. **Test your changes**:
   ```bash
   make test
   make lint
   ```

4. **Commit your changes** with a clear message describing the change

5. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create a pull request** to the main repository

7. **Address any feedback** from the code review

## Ethical Guidelines

Please ensure that any contributions adhere to the ethical usage principles of this project:

- Features should be designed for educational or legitimate security testing purposes
- Consider potential misuse and implement appropriate safeguards
- Document proper usage scenarios and any necessary warnings

## Reporting Bugs

1. Search [existing issues](https://github.com/TMHSDigital/subenum/issues) first to avoid duplicates.
2. Open a new issue using the **Bug Report** template.
3. Include:
   - The exact command you ran
   - Your OS, Go version, and `subenum` version (`./subenum -version`)
   - Full terminal output (redact any sensitive domain names)
   - Expected vs. actual behaviour

Do NOT include sensitive information, unauthorized scan results, or private domain details.

## Suggesting Features

1. Search [existing issues](https://github.com/TMHSDigital/subenum/issues) to avoid duplicates.
2. Open a new issue using the **Feature Request** template.
3. Describe:
   - The problem the feature solves
   - Your proposed solution
   - Legitimate security testing use cases it enables

Features that could primarily enable malicious use will be declined.

## Simulation Mode for Development

Use `-simulate` to develop and test without making real DNS queries:

```bash
./subenum -simulate -hit-rate 30 -w examples/sample_wordlist.txt example.com
```

This lets you iterate on output formatting, flag handling, and new features safely.

## Testing Requirements

All pull requests must pass the full test suite, including the race detector:

```bash
go test -v -race ./...
```

New features should include tests. New flags must be covered by at least one test case.
Do not hit public resolvers. Use `-simulate` or the in-process DNS server in
`internal/dnstest`, which answers from a per-query handler (records, RCODE,
NODATA, delay, drop, truncation) and counts every query per name and type.
`internal/dns` tests can also use the table-driven `startTestDNS` wrapper in
`internal/dns/testdns_test.go`. The optional live smoke test is gated on
`SUBENUM_NETWORK_TESTS=1`.