---
layout: default
title: CLI reference
description: Every subenum flag, its default, the exit codes, and where settings can come from.
---

# CLI reference

```bash
subenum [flags] <domain>
subenum [flags] -dL domains.txt
```

Flags may appear before or after the domain. A URL, a port or an internationalized name is normalized to the apex domain before scanning.

## Flags

{% include flags.md %}

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Failure |
| `2` | Invalid arguments or configuration |
| `3` | Some `-dL` targets failed |
| `4` | `-diff` found added or removed names |
| `130` | Interrupted (Ctrl+C) |
| `143` | Terminated (SIGTERM) |

## Defaults from the environment or a file

Settings you repeat on every run can live in the environment or a config file. Precedence, highest first: **command-line flag, then `SUBENUM_*` environment variable, then config file, then built-in default.**

- Each flag reads `SUBENUM_<FLAG>`, upper-cased with dashes as underscores: `SUBENUM_DNS_SERVER`, `SUBENUM_RATE`, `SUBENUM_T`.
- The config file is `config.json` in your user config directory (`~/.config/subenum/` on Linux, `~/Library/Application Support/subenum/` on macOS, `%AppData%\subenum\` on Windows), or the path in `SUBENUM_CONFIG`. Keys are flag names; values are strings, numbers or booleans, and `exclude` and `type` also take a list of strings. Mode flags (`tui`, `version`, `print-config`, `resume`) are command-line only.
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

Resolved names go to stdout and nothing else does, so `subenum example.com | httpx` works as expected. Progress, warnings and the per-outcome breakdown go to stderr. `-o` writes the same results to a file in the chosen `-format`; results files are replaced atomically.
