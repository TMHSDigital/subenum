---
layout: default
title: Roadmap
---

# Roadmap

A prioritized, PR-sized plan derived from the Phase 1 review. Items are grouped
correctness first, then parity/consistency, then documentation, then cleanup and
tests. Within each group the order is chosen so PRs merge cleanly with minimal
conflicts.

Effort: S (under ~1 hour), M (a few hours), L (a day or more).

## Correctness

### C1 (DEFERRED -> tracked in #23). Guard the events sends against a non-draining consumer
- **Status:** deferred; `runner.go` is intentionally left untouched. The full reasoning (both the `EventResult` and `EventDone` sends are unguarded, why guarding only the result send relocates the stall, and the `EventDone`-on-cancel semantics the TUI depends on) lives in issue #23 so it survives independent of this file and is searchable when someone adds a consumer that stops draining.
- **Resolve when:** a consumer that stops draining the events channel actually exists. Fix both sends together with a runner test that hangs without the guard and passes with it.

### C2. Remove dead `dns.Resolve` and its doc reference in the same commit
- **Rationale:** `dns.Resolve` has no callers; it is the superseded `LookupHost` path. ARCHITECTURE section 2.3 names it by signature (`:71`, `:80-81`), so the function and the doc that names it must be corrected together, otherwise the docs reference a deleted symbol for the rest of the project. This overrides the general "docs land after code" rule for the specific case of a doc that names a deleted function.
- **Files:** `internal/dns/resolver.go`, `docs/ARCHITECTURE.md` (section 2.3 only)
- **Effort:** S
- **Independent PR:** yes. Land before D1 so the data-flow rewrite builds on the corrected 2.3.

## Parity and consistency

### P1. Extract validators into `internal/validate`, used by both CLI and TUI
- **Rationale:** the CLI enforces domain syntax and `ip:port` format (`validateDomain`/`validateDNSServer` in `main.go`); the TUI form does not validate either today, only non-empty. On a security tool this is a real parity gap, not tidiness. Extract the regex and the `ip:port` checks into `internal/validate` and import from both `main` and `internal/tui`. Duplicating them into the TUI would leave two copies to drift.
- **Files:** new `internal/validate` package, `main.go`, `internal/tui/form.go`
- **Effort:** M (the extraction is the bulk; the TUI call site is small)
- **Independent PR:** yes. Must land before P2-P4 since they reuse the shared package.

### P2. Persist and round-trip record types (`-type`) in the TUI
- **Rationale:** record-type selection is CLI-only. Add a form field, persist it, and wire `Types` into the TUI `scan.Config`.
- **Files:** `internal/tui/form.go`, `internal/tui/config.go`, `internal/tui/model.go`
- **Effort:** M
- **Independent PR:** yes. Depends on P1.

### P3. Expose recursive enumeration (`-recursive`/`-depth`) in the TUI
- **Rationale:** recursion is CLI-only. Add a Recursive toggle and a Depth field, persist both, wire `Recursive`/`Depth` into the config.
- **Hidden complexity:** Depth must be gated on Recursive exactly the way Hit Rate is gated on Simulate today. That means touching the `fieldCount` const block, the `inputForField` map, and the `moveFocus` skip logic, not just adding a field.
- **Files:** `internal/tui/form.go`, `internal/tui/config.go`, `internal/tui/model.go`
- **Effort:** M
- **Independent PR:** yes. Order after P2 to avoid form-layout conflicts.

### P4. Expose rate limiting (`-rate`) in the TUI
- **Rationale:** rate limiting is CLI-only. Add a Rate field, persist it, wire `Rate` into the config.
- **Files:** `internal/tui/form.go`, `internal/tui/config.go`, `internal/tui/model.go`
- **Effort:** S
- **Independent PR:** yes. Order after P3.

### P5 (DONE). Output file and format in the TUI
- **Decision:** the TUI exposes an optional output-file field plus a format field; `-format` applies only to that file, and the live viewport stays human-readable. A buffered JSON array in a scrolling viewport would be meaningless, so structured output is file-only.
- **Implementation:** added `output.NewFile`, a file-only `Writer` that never touches stdout (writing results to stdout would corrupt the alt-screen). `resultMsg` now carries the resolved records; the model opens the file in `beginScan`, mirrors each result to it, and finalizes on completion. To match the CLI, `Finish` runs only on `EventDone` (success or user abort, both of which still emit `EventDone` with partial counts); the early-error path closes the file without finalizing so no empty JSON array is written.
- **Files:** `internal/output/writer.go`, `internal/tui/form.go`, `internal/tui/config.go`, `internal/tui/model.go`, `internal/tui/scan_view.go`
- **Effort:** L
- **Independent PR:** yes.

## Documentation

These move up to land right after the correctness group. None of P2-P5 touch
`runner.go`, so there is no code-after-docs dependency holding D1 back, and
ARCHITECTURE is currently self-contradictory (section 2.4 describes the
dispatcher-owned queue while section 3 still describes the old "wordlist
processing closes the subdomains channel" model). Holding the fix to the end
would let that contradiction survive the whole project for no reason.

### D1. Rewrite the ARCHITECTURE data-flow to the dispatcher model
- **Rationale:** the Data Flow section (`:138-170`) and section 4.4 (`:198`) still describe a removed feed-then-close `subdomains` channel, contradicting section 2.4 and `runner.go`. Also adds the flags missing from the flow (`-format`, `-rate`, `-type`, `-recursive`, `-depth`). The `dns.Resolve`/`LookupHost` reference in section 2.3 is handled in C2, so D1 leaves 2.3 alone to avoid a double-fix.
- **Files:** `docs/ARCHITECTURE.md` (section 3 / data-flow)
- **Effort:** M
- **Independent PR:** yes. Land after C2.

### D2. Refresh DEVELOPER_GUIDE "Future Development" and file tree
- **Rationale:** the Future Development list (`:257-265`) advertises TUI, output formats, type filtering, recursion, and rate limiting as unshipped; all shipped in 0.5.0/0.6.0. The file tree omits `runner_test.go`.
- **Files:** `docs/DEVELOPER_GUIDE.md`
- **Effort:** S
- **Independent PR:** yes.

### D3. Fix minor doc references
- **Rationale:** `DOCUMENTATION_STRUCTURE.md` cites `logs/CHANGELOG.md` (actual: `CHANGELOG.md`); README and the ARCHITECTURE package blurbs name removed/test-only `dns` functions.
- **Files:** `docs/DOCUMENTATION_STRUCTURE.md`, `README.md`, `docs/ARCHITECTURE.md`
- **Effort:** S
- **Independent PR:** yes. Can fold into D1 if landing together.

## Cleanup

### CL1. Consolidate `SimulateResolution` into `SimulateResolve`
- **Rationale:** `SimulateResolution` is a one-line wrapper over `SimulateResolve` whose only remaining callers are tests (including `TestSimulateResolutionConcurrent`, which exists to be caught by `-race`). This is cleanup with near-zero payoff, not a correctness fix; it carries no implication of a defect. Low priority, land whenever convenient.
- **Files:** `internal/dns/simulate.go`, `internal/dns/simulate_test.go`
- **Effort:** S
- **Independent PR:** yes.

## Tests

### T1. Cover TUI session-config round-trip and form navigation
- **Rationale:** persistence is a shipped feature with zero tests; `saveConfig`/`loadSavedConfig` and the HitRate-skipping navigation are pure and easily testable. Landing last is deliberate: every parity PR changes the form's field set, so writing the navigation and round-trip tests once against the final layout avoids churn.
- **Files:** new `internal/tui/config_test.go`, `internal/tui/form_test.go`
- **Effort:** M
- **Independent PR:** yes. Land after the parity group settles.

### T2. Cover output simulate-prefix and CSV empty-record branches
- **Rationale:** untested branches in the output writer (the `simulate` text prefix, the CSV zero-record fallback row).
- **Files:** `internal/output/writer_test.go`
- **Effort:** S
- **Independent PR:** yes.

## Suggested merge order

C2 -> D1, D2, D3 -> P1 -> P2 -> P3 -> P4 -> P5 -> CL1 -> T1, T2.

C1 is deferred (see above) and is not in the sequence; `runner.go` is left
untouched. C2 corrects the ARCHITECTURE 2.3 `Resolve` reference in the same
commit that deletes the function, so D1 (data-flow rewrite) builds on a
corrected section. D1-D3 are independent of the parity work and land early to
kill the ARCHITECTURE contradiction. P1 introduces the shared `internal/validate`
package that P2-P5 consume; extraction is the committed choice, not an option,
because every subsequent parity PR adds fields that need validation and
duplicated validators would have to be kept in sync across two copies forever.
P2-P5 each touch the same TUI files, so they are sequenced to avoid form-layout
merge conflicts. CL1 is low-priority cleanup that can slot in anywhere after the
C group. Tests trail so they assert against the final form layout.

---

## Proposed CHANGELOG "Unreleased" entries

Matching the existing Keep a Changelog sections and the no-em-dash convention.

```
### Added
- TUI now exposes record-type selection (`-type` parity): a Types field is added to the form, persisted to `last.json`, and wired into the scan config.
- TUI now exposes recursive enumeration: a Recursive toggle and a Depth field gated on it, persisted across sessions and wired into the scan config (`-recursive`/`-depth` parity).
- TUI now exposes a rate-limit field paced across the worker pool, persisted across sessions (`-rate` parity).
- TUI can write resolved results to a file in the selected format (`text`, `json`, or `csv`), persisted across sessions. The format applies only to the file; the live viewport stays human-readable. Backed by a new file-only `output.NewFile` writer so structured output never collides with the alt-screen.

### Changed
- TUI form now validates domain syntax and DNS server `ip:port` format up front, matching the CLI. The validators were extracted into a shared `internal/validate` package used by both the CLI and the TUI (previously the form only checked for non-empty values).

### Removed
- Removed the unused `dns.Resolve` function, superseded by `dns.ResolveTypes`.
- Consolidated the simulation helpers onto a single `dns.SimulateResolve`, removing the test-only `SimulateResolution` wrapper.

### Docs
- Rewrote the ARCHITECTURE data-flow section to describe the dispatcher-owned work queue instead of the removed feed-then-close `subdomains` channel, and corrected the DNS engine function descriptions.
- Refreshed the DEVELOPER_GUIDE "Future Development" section to remove features that already shipped (TUI, output formats, record-type filtering, recursive enumeration, rate limiting) and added the missing `runner_test.go` to the file tree.
- Fixed stale references: the `DOCUMENTATION_STRUCTURE.md` changelog path and the `dns` package function names in README and ARCHITECTURE.

### Tests
- Added TUI tests for session-config round-trip (`saveConfig`/`loadSavedConfig`) and form navigation, and output-writer tests for the simulate text prefix and the CSV empty-record fallback row.
```
