# Documentation map

Where each piece of subenum's documentation lives and who it is for. The files under `docs/` are also the [project site](https://tmhsdigital.github.io/subenum/); this page is left out of the site build.

## For users

| Document | What it covers |
|---|---|
| [`README.md`](../README.md) | What subenum is, install, quick start, every flag, output formats, the TUI, completions and the man page |
| [`docs/start.md`](start.md) | First scan, the run-quality verdict, what to read next |
| [`docs/cli.md`](cli.md) | CLI reference: flags (generated from the code into [`_includes/flags.md`](_includes/flags.md)), exit codes, config file and `SUBENUM_*` defaults |
| [`docs/pipelines.md`](pipelines.md) | Chaining with dnsx, httpx and nuclei; JSON logs; takeover candidates first |
| [`docs/monitoring.md`](monitoring.md) | Scheduled scans with `-diff`, the GitHub Action ([`action.yml`](../action.yml)) and SARIF alerts |
| [`docs/docker.md`](docker.md) | The container image: volumes, output files, permissions |
| [`docs/labs.md`](labs.md) | Offline exercises against [`examples/labs/`](../examples/labs/) zones with `-simulate-zone` |
| [`docs/library.md`](library.md) | The Go library `pkg/subenum`; the full API reference is on pkg.go.dev |
| [`docs/mcp.md`](mcp.md) | `subenum mcp`: its tools, the operator's flags and caps, client setup |
| [`examples/advanced_usage.md`](../examples/advanced_usage.md) | Longer recipes: wildcards, record types, rate limiting, the reliability guard, CSV |
| [`tools/README.md`](../tools/README.md) | The `wordlist-gen` tool |

## For contributors

| Document | What it covers |
|---|---|
| [`docs/CONTRIBUTING.md`](CONTRIBUTING.md) | Setup, tests, lint, pull requests |
| [`docs/DEVELOPER_GUIDE.md`](DEVELOPER_GUIDE.md) | Project tree, hermetic testing, previewing the site, extension points |
| [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) | How the engine works: packages, resolution, dispatch, output, error handling |
| [`docs/ROADMAP.md`](ROADMAP.md) | Where the project is heading and known constraints |
| [`docs/CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) | Community expectations |

## Project files

| File | What it covers |
|---|---|
| [`CHANGELOG.md`](../CHANGELOG.md) | Changes per release (Keep a Changelog); each release's notes come from its section |
| [`SECURITY.md`](../SECURITY.md) | Supported versions and how to report a vulnerability |
| [`LICENSE`](../LICENSE) | GPL-3.0 |
| [`CITATION.cff`](../CITATION.cff) | How to cite subenum |

## Keeping docs current

- Regenerate the site's flag table with `make docs-flags`; `go test .` fails when it or the README flag table drifts from the CLI.
- List anything on `main` but not yet released in [`_data/unreleased.yml`](_data/unreleased.yml) so the site tags it, and empty the lists in the release commit.
