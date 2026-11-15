---
layout: default
title: CLI reference
description: Every subenum flag, its default, the exit codes, and where settings can come from.
---

# CLI reference

```bash
subenum [flags] <domain>
subenum [flags] -dL domains.txt
subenum completion bash|zsh|fish|powershell
subenum man
subenum diff [-records] [-type A,AAAA,CNAME] [-format text|json|jsonl|csv] <previous> <current>
subenum mcp [-allow domains] [flags]
```

Flags may appear before or after the domain. The domain is normalized to its host name before scanning: a URL's scheme and path, a `:port` and a leading `*.` are removed and an internationalized name becomes punycode, so `https://app.example.com/login` scans `app.example.com`, not `example.com`.

`completion` prints a shell completion script and `man` prints the man page, both generated from the same flags; release archives ship them under `completions/` and `man/`. `mcp`{% include unreleased.html command="mcp" %} serves subenum to AI agents over the Model Context Protocol, within the domains, resolver and budgets you give it; see [AI agents (MCP)](mcp.html) for its flags.

`diff`{% include unreleased.html command="diff" %} compares two saved results files, in any format subenum writes, without sending a DNS query. It prints `+ name` for names only in `<current>` and `- name` for names only in `<previous>` (`change` is `added` or `missing` in JSON, JSONL and CSV). A missing name is not proven gone, since nothing is looked up; `-diff` during a scan checks each one with a fresh lookup first. `-records` also prints `~ name` (`changed`) for names in both files whose records differ, compared as `-diff-records` does over the `-type` record types (every type by default); it needs JSON, JSONL or CSV files, and compares names only otherwise. The exit code is `4` when the files differ.

## Flags

{% include unreleased-note.html %}

{% include flags.md %}

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Failure |
| `2` | Invalid arguments or configuration |
| `3` | Some `-dL` targets failed |
| `4` | `-diff` found added or removed names (or, with `-diff-records`, changed records); `subenum diff` found differences |
| `130` | Interrupted (Ctrl+C) |
| `143` | Terminated (SIGTERM) |

## Defaults from the environment or a file

Settings you repeat on every run can live in the environment or a config file. They apply to scans (and `-tui`), not to the `mcp` subcommand, which takes its settings from its own flags only. Precedence, highest first: **command-line flag, then `SUBENUM_*` environment variable, then config file, then built-in default.**

- Each flag reads `SUBENUM_<FLAG>`, upper-cased with dashes as underscores: `SUBENUM_DNS_SERVER`, `SUBENUM_RATE`, `SUBENUM_T`.
- The config file is `config.json` in your user config directory (`~/.config/subenum/` on Linux, `~/Library/Application Support/subenum/` on macOS, `%AppData%\subenum\` on Windows), or the path in `SUBENUM_CONFIG`. Keys are flag names; values are strings, numbers or booleans, and `exclude` and `type` also take a list of strings. Mode flags (`tui`, `version`, `print-config`, `dry-run`, `resume`) are command-line only.
- The TUI (`-tui`) starts its form from these values too, and from flags and the domain given with `-tui` on the command line, over the values it remembers from its last session.
- `subenum -print-config` prints every effective setting and where it came from: `flag`, `env`, `config` or `default`. With a bad value, `-h`, `-version` and `-print-config` still run and warn; a scan refuses to start and names every bad value.
- When `-attempts` and the deprecated `-retries` both have a value, the one from the higher-precedence source wins; both on the command line (or both from the same file) is an error.

```json
{
  "dns-server": "tls://1.1.1.1",
  "rate": 200,
  "type": "A,AAAA,CNAME"
}
```

## Output streams

Resolved names go to stdout and nothing else does, so `subenum example.com | httpx` works as expected. Progress, warnings and the per-outcome breakdown go to stderr. `-o` writes the same results to a file in the chosen `-format`; results files are replaced atomically. Repeat `-o` to write several files; a file without a prefix uses `-format`, and a prefix names its own format: `-o text:names.txt -o jsonl:results.jsonl`{% include unreleased.html value="o=format:path" %} writes bare names and JSONL in one run, whatever `-format` stdout uses.
