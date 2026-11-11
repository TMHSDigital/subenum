---
layout: default
title: Pipelines
description: Chain subenum with dnsx, httpx and nuclei, and gate each step on the run-quality verdict.
---

# Pipelines

subenum is built to sit at the start of a recon pipeline. With `-silent`,
stdout carries one resolved name per line and nothing else, and stderr carries
only errors, so its output pipes straight into the next tool. Even without
`-silent`, results go to stdout and everything else to stderr, and piped text
output is already bare names.

Only scan domains you own or are authorized to test. Every recipe below works
offline against a [lab zone](labs.html) first:

```bash
subenum -silent -simulate-zone examples/labs/lab1-first-scan.zone lab.example
```

## Resolve, probe, scan

```bash
# Names with their A records (dnsx re-resolves them; subenum already did,
# so this is for formatting or a second resolver's opinion).
subenum -silent example.com | dnsx -silent -a -resp

# Live web services: status, title and technologies.
subenum -silent example.com | httpx -silent -status-code -title -tech-detect

# Subdomain takeover checks on every name found.
subenum -silent -type A,AAAA,CNAME example.com | nuclei -silent -tags takeover
```

## Gate the pipeline on the verdict

A scan that hit a rate-limiting resolver can return a fraction of the real
names and still exit 0. The [run-quality report](cli.html) says whether the
result set can be trusted, so check it before spending time downstream:

```bash
subenum -silent -stats run.json -o names.txt example.com
if ! jq -e '.verdict == "complete"' run.json > /dev/null; then
  jq -r '"subenum run was \(.verdict): \(.reason)"' run.json >&2
  exit 1
fi
httpx -silent -l names.txt
```

With `-format jsonl`, the same report is the last line of the output, so one
file holds both:

```bash
subenum -silent -format jsonl -o results.jsonl example.com > /dev/null
tail -n 1 results.jsonl | jq -e '.verdict == "complete"' > /dev/null || exit 1
jq -r 'select(.type != "summary") | .subdomain' results.jsonl | httpx -silent
```

## Takeover candidates first

With CNAME lookups, subenum marks names whose alias target does not resolve or
points at a takeover-prone service. Send those to a closer look before the
rest:

```bash
subenum -silent -format jsonl -type A,AAAA,CNAME example.com \
  | jq -r 'select(.takeover_candidate) | "\(.subdomain)\t\(.takeover_candidate)"'
```

## Names that resolve to an internal address

A public name that resolves to a private, loopback, link-local or CGNAT
address leaks the internal network layout, and a loopback answer can matter
for DNS rebinding. Those names carry an `internal_address` with the scope:

```bash
subenum -silent -format jsonl example.com \
  | jq -r 'select(.internal_address) | "\(.subdomain)\t\(.internal_address)"'
```

The run summary counts them (`internal_addresses` in the `-stats` report).

## Many targets

`-dL` scans a list of apex domains with one combined output; each target gets
its own preflight, wildcard check and verdict in the report:

```bash
subenum -silent -dL scope.txt -exclude-file out-of-scope.txt -stats run.json \
  | httpx -silent
```

## Machine-readable diagnostics

`-log-format json`{% include unreleased.html flag="log-format" %} turns stderr into JSON Lines, so CI can act on a warning
without matching `Note:` or `Warning:` text. Each line has `time`, `level`
(`error`, `warn`, `notice`, `info`, `debug`), `kind`, `target` (the domain
being scanned, when there is one) and `message`; engine notices also list the
settings they name as codes in `settings`. Results on stdout are unchanged:

```bash
subenum -log-format json -stats run.json example.com 2> log.jsonl > names.txt
jq -r 'select(.level == "warn" or .level == "error") | "\(.kind): \(.message)"' log.jsonl
```

```json
{"time":"2026-11-09T12:00:00.000Z","level":"warn","kind":"cap","target":"example.com","message":"query cap reached (-max-queries 3); skipped 3 additional jobs","settings":["max_queries"]}
```

Progress is an event (`"kind":"progress"` with a `progress` object of
`percent`, `processed`, `total`, `found` and `eta_seconds`) and, as on a piped
stderr, appears only when `-progress` is given explicitly. Errors in the
command line itself are JSON lines too, once `-log-format json` has been read
(from the command line before the error, `SUBENUM_LOG_FORMAT` or the config
file); `-h` help stays text.

## Tips

- Pace the scan with `-rate` when the next tool shares the same resolver or
  network budget; subenum counts every wire query against it.
- `-silent` still prints a one-line warning when results are simulated
  (`-simulate`), so a test run cannot be mistaken for a real one.
- For change detection over time, see [Monitoring](monitoring.html).
