# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
