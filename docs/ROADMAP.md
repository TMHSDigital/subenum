---
layout: default
title: Roadmap
---

# Roadmap

Status as of v0.7.0. Items below the fold are the next pass; they were
noticed during resolver-layer hardening and left alone on purpose.

Effort: S (under ~1 hour), M (a few hours), L (a day or more).

## Shipped in 0.6.x / 0.7.0

### C1 (DEFERRED -> tracked in #23). Guard the events sends against a non-draining consumer
- **Status:** deferred; `runner.go` is intentionally left untouched. The full reasoning lives in issue #23.
- **Resolve when:** a consumer that stops draining the events channel actually exists. Fix both sends together with a runner test that hangs without the guard and passes with it.

### C2 (DONE). Remove dead `dns.Resolve` and its doc reference
Landed with the unused `LookupHost` path deleted and ARCHITECTURE section 2.3 corrected.

### P1 (DONE). Extract validators into `internal/validate`
CLI and TUI share `validate.Domain` and `validate.DNSServer`. As of 0.7.0 the domain
validator also enforces the 63-character per-label limit and accepts punycode TLDs (`xn--...`).

### P2 (DONE). Persist and round-trip record types (`-type`) in the TUI

### P3 (DONE). Expose recursive enumeration (`-recursive`/`-depth`) in the TUI

### P4 (DONE). Expose rate limiting (`-rate`) in the TUI

### P5 (DONE). Output file and format in the TUI
`output.NewFile` is file-only so structured output never collides with the alt-screen.

### D1 (DONE). Rewrite the ARCHITECTURE data-flow to the dispatcher model

### D2 (DONE). Refresh DEVELOPER_GUIDE "Future Development" and file tree

### D3 (DONE). Fix minor doc references

### CL1 (DONE). Consolidate `SimulateResolution` into `SimulateResolve`

### T1 (DONE). Cover TUI session-config round-trip and form navigation

### T2 (DONE). Cover output simulate-prefix and CSV empty-record branches

### R1 (DONE). Resolver-layer hardening (v0.7.0)
Outcome classification and scan accounting, NXDOMAIN no-retry, TCP fallback plus
one `*net.Resolver` per scan, wildcard fingerprints and per-branch detection,
`-max-queries` plus recursion ceiling plus resolver preflight, hermetic DNS tests
and release hygiene.

## Next pass

Do not expand this list into drive-by fixes in the same PR that notices them.

### N1. `-rate` ticker implementation
The shared stdlib ticker gate works but is coarse (burst at tick boundaries, no
token bucket). Revisit pacing without changing the `scan.Event` boundary.

### N2. Text-format record display
`text` output still prints `Found: <domain>` and drops record type/value. JSON
and CSV already carry them.

### N3. Per-type shared timeout budget
`ResolveTypes` uses one `context.WithTimeout` for the whole type loop, so AAAA
and CNAME starve after a slow A. Give each type its own budget or a remaining
budget that cannot go negative.

### N4. `-dL` multi-domain input
A domain-list file (one apex per line) so a single process can scan more than
one target. Needs a clear interaction with `-recursive`, `-max-queries`, and
the reliability guard.

### N5. Verbose/progress stderr interleaving
`-v` and `-progress` write to stderr without coordination, so verbose lines can
overwrite the carriage-return progress line.

### N6. TUI viewport clamp
The scan-view viewport can scroll past content or fail to follow the tail on
fast result streams.

### N7. Event-channel send guards (C1 / #23)
Still deferred until a non-draining consumer exists.
