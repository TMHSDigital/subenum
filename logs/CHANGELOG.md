# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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