---
layout: default
title: Monitoring
---

# Continuous monitoring with `-diff`

For your own infrastructure, the useful question is often not "what exists" but
"what is new since last week". New subdomains are where forgotten staging hosts
and takeover risks appear. `-diff` turns subenum into a change detector.

## How `-diff` works

```bash
# First run: keep the full results.
subenum -w wordlist.txt -format jsonl -o previous.jsonl example.com

# Later runs: report only what changed, and keep the new full results.
subenum -w wordlist.txt -format jsonl -diff previous.jsonl -o current.jsonl example.com
```

- `-diff` reads a previous results file in any format subenum writes (text,
  `-show-records` text, JSON, JSONL or CSV).
- Only changes are printed. Text lines are `+ name` (added) or `- name`
  (removed); JSON and JSONL results carry `"change": "added"` or
  `"change": "removed"`; CSV gains a `change` column.
- The `-o` file still receives the **full** current results, so it can be the
  next run's `-diff` input.
- The exit code is `4` when anything was added or removed, `0` when nothing
  changed. A failed scan still exits `1`, `2` or `3`.
- Names are only reported as removed when the run's
  [quality verdict](https://github.com/TMHSDigital/subenum#run-quality-report) is `complete`. A name
  missing from a degraded run may just be a lookup that failed, so removals are
  suppressed with a note instead. Names under `-exclude` patterns are never
  reported as removed.
- A previous name this run did not find is looked up again with the trusted
  resolver before it is reported, and only an NXDOMAIN answer counts as
  removed. A name the current wordlist cannot produce (a smaller list, no
  `-recursive` or `-permute`) still resolves, and a name whose lookup fails
  cannot be checked; neither is reported as removed, and stderr says how many
  there were.
- With `-stats` (or `-format jsonl`), the run-quality report gains a `diff`
  object with the `added` and `removed` counts, plus `still_resolving` and
  `unverified` when there were any.

## Example: a scheduled GitHub Actions workflow

This workflow scans every Monday, keeps the previous results in the Actions
cache, and opens an issue when new names appear. Commit your wordlist as
`wordlist.txt`, set `TARGET` to a domain you own, and save it as
`.github/workflows/subdomain-monitor.yml`.

```yaml
name: Subdomain monitor

on:
  schedule:
    - cron: "0 6 * * 1"   # Mondays 06:00 UTC
  workflow_dispatch:

permissions:
  contents: read
  issues: write

env:
  TARGET: example.com     # a domain you own or are authorized to scan

jobs:
  monitor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5

      - uses: actions/setup-go@v6
        with:
          go-version: stable

      - name: Install subenum
        # -diff ships after v0.8.0; pin the first release tag that includes it
        # once one exists, instead of tracking main.
        run: go install github.com/TMHSDigital/subenum@main

      - name: Restore previous results
        uses: actions/cache/restore@v4
        with:
          path: previous.jsonl
          key: subenum-${{ env.TARGET }}-${{ github.run_id }}
          restore-keys: subenum-${{ env.TARGET }}-

      - name: Scan
        id: scan
        run: |
          if [ -s previous.jsonl ]; then echo "baseline=true" >> "$GITHUB_OUTPUT"; else : > previous.jsonl; fi
          set +e
          subenum -w wordlist.txt -format jsonl -diff previous.jsonl \
            -o current.jsonl -stats run.json "$TARGET" > changes.jsonl
          code=$?
          echo "code=$code" >> "$GITHUB_OUTPUT"
          jq -r '"verdict: \(.verdict) (\(.reason))"' run.json
          # 0 = no changes, 4 = changes; anything else is a failed scan.
          [ "$code" -eq 0 ] || [ "$code" -eq 4 ]

      - name: Open an issue for new names
        # Skip the very first run, when every name is "added".
        if: steps.scan.outputs.code == '4' && steps.scan.outputs.baseline == 'true'
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          added=$(jq -r 'select(.change == "added") | "- \(.subdomain)"' changes.jsonl)
          [ -n "$added" ] || exit 0
          printf 'subenum found new subdomains of %s since the last scan:\n\n%s\n' "$TARGET" "$added" > body.md
          gh issue create --repo "$GITHUB_REPOSITORY" \
            --title "New subdomains of $TARGET ($(date -u +%F))" --body-file body.md

      - name: Keep the current results for next time
        run: mv current.jsonl previous.jsonl

      - name: Save results
        uses: actions/cache/save@v4
        with:
          path: previous.jsonl
          key: subenum-${{ env.TARGET }}-${{ github.run_id }}
```

Actions caches expire after seven days without use, so with a weekly schedule
the baseline is refreshed every run. For a longer gap, store `previous.jsonl`
somewhere durable (an artifact, a branch, or object storage) instead.

A webhook works the same way as the issue step: post `changes.jsonl` (or the
`added` names) to Slack, Teams or your alerting endpoint.
