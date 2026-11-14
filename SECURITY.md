# Security Policy

## Supported Versions

Security fixes land on `main` and ship in the next release. Only the latest minor release is supported.

| Version | Supported |
|---------|-----------|
| Latest minor release | Yes |
| Older releases | No |

## In Scope

Report these, among anything else that lets input subenum does not control harm its user:

- In `subenum mcp`: a tool call that scans a domain outside the operator's `-allow` list, raises a cap the operator set (`-max-queries`, `-max-duration`, `-rate`, `-max-calls`), picks the resolver, or reads or writes files.
- Data from a scanned zone, a resolver, a passive source (crt.sh, the Wayback Machine) or a zone transfer that subenum passes on unsafely: to the terminal, an output file, the GitHub Action's job summary, or an MCP client.
- The GitHub Action or the release workflow running code or using secrets it should not.

## Reporting a Vulnerability

If you discover a security vulnerability in `subenum`, **do not open a public issue.**

Report it privately using GitHub's Security Advisory feature:
1. Go to the [Security tab](https://github.com/TMHSDigital/subenum/security/advisories/new) of this repository.
2. Click **"Report a vulnerability"**.
3. Fill in the description, reproduction steps, and impact.

This is a small project, so responses are best effort: expect an acknowledgment typically within a week. We will investigate, share a fix timeline, keep you informed, and credit you upon resolution (unless you prefer anonymity).

## Responsible Usage

`subenum` is designed for:
- Educational purposes
- Authorized security testing

Scanning systems without explicit permission may be illegal where you are, and it is outside the project's intended use. The GPL-3.0 license itself does not restrict how the software is used; that responsibility is yours.

## Thank You

Security researchers and responsible disclosure are vital to maintaining secure software. We appreciate your efforts to disclose vulnerabilities responsibly.
