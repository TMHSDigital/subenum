---
layout: default
title: Roadmap
---

# Roadmap

Where subenum is going next. Everything that has shipped is in the
[CHANGELOG](https://github.com/TMHSDigital/subenum/blob/main/CHANGELOG.md);
this page only lists open work. Each item links to its issue, which is the place
to discuss it or offer help.

## Now

Work in progress or next up.

- **v0.9.0** ([#104](https://github.com/TMHSDigital/subenum/issues/104)): the
  first release with the library API, lab mode, DoT/DoH, resume, permutations,
  monitoring and config defaults, built by GoReleaser with static binaries
  ([#46](https://github.com/TMHSDigital/subenum/issues/46)), checksums, SBOMs
  and attestations.

## Next

Planned features that make results more trustworthy and the tool easier to get.

- **A packaged GitHub Action** for scheduled monitoring, building on `-diff`
  and the example workflow in [Monitoring](monitoring.html)
  ([#126](https://github.com/TMHSDigital/subenum/issues/126)).
- **Package managers** ([#62](https://github.com/TMHSDigital/subenum/issues/62)):
  Homebrew, Scoop, AUR, Nix, Kali/BlackArch.
- **Certificate Transparency seeding** (`-ct`) to feed permutations and brute
  force without API keys ([#130](https://github.com/TMHSDigital/subenum/issues/130)).
- **A reproducible benchmark** against other DNS brute-forcers on lab zones
  ([#127](https://github.com/TMHSDigital/subenum/issues/127)).

## Later

Ideas we want, with no date attached.

- Try AXFR and detect NSEC-walkable zones before brute-forcing ([#85](https://github.com/TMHSDigital/subenum/issues/85)).
- Discoverability: demo GIF and launch posts ([#74](https://github.com/TMHSDigital/subenum/issues/74)).
- Pipelines guide and `-silent` for chaining with dnsx, httpx and nuclei ([#128](https://github.com/TMHSDigital/subenum/issues/128)).
- SARIF output for takeover candidates ([#129](https://github.com/TMHSDigital/subenum/issues/129)).
- An MCP server mode for budgeted scans by AI agents ([#131](https://github.com/TMHSDigital/subenum/issues/131)).

## What 1.0 means

subenum reaches 1.0 when scripts and pipelines can depend on it without
surprises:

- **Stable flags.** No flag is renamed or removed without a deprecation release
  first (as `-retries` was for `-attempts`).
- **Stable output schemas.** The JSON, JSONL and CSV fields are documented and
  only ever gain fields, never lose or rename them.
- **Documented exit codes**, already in place (0, 1, 2, 3, 4, 130, 143).
- **A run-quality report**, already in place (`-stats`, schema 1), so a result
  set says how far it can be trusted.
- **Verifiable releases**, in place from the next release: checksums, SBOMs,
  cosign signatures and provenance attestations.
- **A stable library API.** `pkg/subenum` follows semantic versioning from 1.0;
  until then it may change between minor releases.

## Known limitations

Constraints to keep in mind when changing the code.

- **The test DNS server (`internal/dnstest`) models A, AAAA and CNAME
  answers,** any RCODE, NODATA with SOA, delays, drops and truncation. Other
  record types and EDNS are not modelled; extend its `Reply` before testing
  them.
- **DNS goes through Go's stdlib resolver.** Its internal retries depend on the
  host's resolver configuration. `-rate` charges every query it dials, but the
  number of queries per lookup is not fully under subenum's control.
- **IDN targets use a plain RFC 3492 Punycode encoder**, not full UTS #46
  mapping, so a domain must be typed in its usual lowercase form.
- **The reliability guard is tested with injected timeouts, not simulate
  misses,** because simulate misses classify as NXDOMAIN, which is excluded from
  the failure rate by design.
- **The `go` directive is pinned at `1.26.0`** and CI checks it. New
  dependencies must keep it and pass `govulncheck` in CI. On PowerShell, quote
  `-go=1.26.0`; unquoted it is parsed as `-go=1`.
