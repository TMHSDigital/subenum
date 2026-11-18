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
  next run's `-diff` input. With several `-o` files, each one does, in its own
  format. If a stopped run saves state for `-resume`, an `-o` file that is also
  the `-diff` file is left unchanged; the others get the partial results.
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
- These checks spend what is left of the run's budgets: `-max-queries` per
  target, less the names the scan tested, and the `-max-duration` deadline.
  Names the budget does not reach are counted `unverified`, not removed.
- With `-stats` (or `-format jsonl`), the run-quality report gains a `diff`
  object with the `added` and `removed` counts, plus `still_resolving` and
  `unverified` when there were any.

### Record changes: `-diff-records`

A name can stay in place while what it points at moves. A CNAME re-pointed
at an unclaimed service is a takeover waiting to happen, and plain `-diff`
reports it as unchanged. Add `-diff-records`{% include unreleased.html flag="diff-records" %} to also compare the records of
every name found again:

```bash
subenum -w wordlist.txt -format jsonl -type A,AAAA,CNAME -diff previous.jsonl -diff-records -o current.jsonl example.com
```

- A changed name is printed as `~ name` (with `-show-records`, the new
  records and `(was ...)`), or carries `"change": "changed"` and
  `"previous_records"` in JSON and JSONL. It counts as `changed` in the report's
  `diff` object, and the exit code is `4`.
- Records are compared as sets, over the record types this run looks up, so
  use the same `-type` as the previous run. When either side has a CNAME, only
  the CNAME targets are compared: the addresses behind a CDN alias rotate with
  every TTL and would otherwise flag every CDN host.
- The previous file must carry records: JSON, JSONL or CSV. A text file has
  none, so the comparison falls back to names with a note.
- A name whose lookup of one type still failed after `-attempts` while another
  type answered is marked `"partial": true` and is never reported as changed:
  its missing records may only be a lookup that timed out. Partial answers
  lower the run's verdict as failed lookups do.

## The subenum GitHub Action

The repository is also a GitHub Action. It installs a release (checked against
its `checksums.txt` and its build provenance attestation), diffs against the previous complete run's results kept as
an artifact, writes a summary table to the job, and fails the job when the
verdict is not good enough:

```yaml
name: Subdomain monitor
on:
  schedule:
    - cron: "0 6 * * 1"
  workflow_dispatch:

permissions:
  contents: read
  actions: read
  security-events: write   # only for the SARIF upload

jobs:
  monitor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7
      - id: subenum
        uses: TMHSDigital/subenum@v0.11.0  # pin a release, or its commit SHA
        with:
          domain: example.com            # a domain you own or may test
          wordlist: wordlist.txt
          args: -rate 200 -type A,AAAA,CNAME -ct
          baseline-artifact: subenum-example.com
          sarif: takeovers.sarif
          fail-on: degraded
      - if: always() && hashFiles('takeovers.sarif') != ''
        uses: github/codeql-action/upload-sarif@33d7b85da1a04171e211befe2c739303b9a4c066 # v4
        with:
          sarif_file: takeovers.sarif
          category: subenum
```

| Input | Default | Meaning |
|---|---|---|
| `domain` / `domains-file` | | What to scan (one of them) |
| `wordlist` | bundled top 5000 | `-w` |
| `args` | | Extra flags, separated by spaces or newlines (an `args: \|` block works) |
| `previous` | | A previous results file to diff against (add `-diff-records` to `args` to also catch record changes) |
| `baseline-artifact` | | Artifact name for the baseline: downloaded before, replaced after a complete run. Only an artifact that the same workflow uploaded from the default branch, outside pull requests, is used. A run that `max-duration` stops saves its resume state there too, and the next run continues that scan |
| `sarif` | | Write takeover candidates as SARIF |
| `max-duration`{% include unreleased.html action="max-duration" %} | | Time budget, e.g. `20m` (`-max-duration`). Keep it under the job's `timeout-minutes`: a job killed by its timeout leaves no report, while a scan that reaches its budget stops testing new names and still writes results and a `degraded` report. The CLI also saves a resume state then (`subenum-resume.json`, or the `-state` path), and `subenum -resume <file>` tests the names the budget left. With `baseline-artifact`, the action keeps that state in the artifact, next to the previous results it still diffs against, and the next run resumes the scan instead of starting over, so a scheduled job works through a large wordlist over several runs; the baseline is replaced once a run completes. A change to the inputs or to the wordlist file discards the state with a notice and starts a new scan |
| `fail-on` | `unreliable` | Fail on this verdict or worse: `unreliable`, `degraded` or `never`. With `never`, a failed scan (verdict `unreliable`) still passes the step; a usage error or a run with no report always fails |
| `version` | `latest` | Release to install, or `source` to build the action's checkout |
| `token` | `github.token` | Token for downloading the release and the baseline artifact |

Outputs: `verdict`, `resumed`{% include unreleased.html action="resumed" %} (`true` when the run continued a stopped scan), `found` (including `-permute` hits), `added`, `removed`, `changed`{% include unreleased.html action="changed" %} (with `-diff-records`),
`takeovers`{% include unreleased.html action="takeovers" %} (takeover candidates among the names found; needs `CNAME` or `NS` in `-type`),
`internal`{% include unreleased.html action="internal" %} (names answering with an address that is not public), and the paths `results` (JSONL),
`stats` (the run-quality report) and `changes`{% include unreleased.html action="changes" %} (JSONL, one line per added, removed or
changed name with a `change` field; empty when there were no previous results to
diff against). The job summary lists the takeover candidates under the table.

To open an issue with the new names, add a step after the action (the job
then also needs `issues: write`). It reads the `changes`{% include unreleased.html action="changes" %}
output, which an action pinned to a release that predates it leaves empty;
the `if:` then skips the step instead of failing it:

{% raw %}
```yaml
      - if: steps.subenum.outputs.added != '0' && steps.subenum.outputs.changes != ''
        env:
          GH_TOKEN: ${{ github.token }}
          CHANGES: ${{ steps.subenum.outputs.changes }}
        run: |
          jq -r 'select(.change == "added") | "- \(.subdomain)"' "$CHANGES" > body.md
          gh issue create --repo "$GITHUB_REPOSITORY" --title "New subdomains ($(date -u +%F))" --body-file body.md
```
{% endraw %}

The step below builds the same thing by
hand, if you prefer to see every command.

## Example: a scheduled GitHub Actions workflow

This workflow scans every Monday, keeps the previous results as a workflow
artifact, and opens an issue when new names appear. Commit your wordlist as
`wordlist.txt`, set `TARGET` to a domain you own, and save it as
`.github/workflows/subdomain-monitor.yml`.

It runs with `issues: write`, so it pins everything it runs: subenum is a
release archive checked against the release's `checksums.txt` (`-diff` first
shipped in v0.9.0), and each action is pinned to a commit.

{% raw %}
```yaml
name: Subdomain monitor

on:
  schedule:
    - cron: "0 6 * * 1"   # Mondays 06:00 UTC
  workflow_dispatch:

permissions:
  contents: read
  actions: read           # download the previous run's results
  issues: write

env:
  TARGET: example.com     # a domain you own or are authorized to scan
  SUBENUM_VERSION: 0.11.0 # a release tag without the "v"

jobs:
  monitor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7

      - name: Install subenum
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          archive="subenum_${SUBENUM_VERSION}_linux_amd64.tar.gz"
          gh release download "v${SUBENUM_VERSION}" --repo TMHSDigital/subenum \
            --pattern "$archive" --pattern checksums.txt
          sha256sum --check --ignore-missing checksums.txt
          tar -xzf "$archive" subenum
          sudo install subenum /usr/local/bin/

      - name: Download previous results
        # The newest results artifact, from the last complete run: unlike a
        # cache, it does not expire after a skipped week (artifacts keep 90
        # days here). A fork's pull request can upload an artifact under the
        # same name, so take only one uploaded from this repository's default
        # branch.
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          branch=$(gh api "repos/$GITHUB_REPOSITORY" --jq .default_branch)
          run=$(gh api "repos/$GITHUB_REPOSITORY/actions/artifacts?name=subenum-results&per_page=100" |
            jq -r --arg b "$branch" 'first(.artifacts[] | select(.expired == false) | .workflow_run
              | select(.head_repository_id == .repository_id and .head_branch == $b) | .id) // empty')
          if [ -n "$run" ]; then
            gh run download "$run" --repo "$GITHUB_REPOSITORY" --name subenum-results
          fi

      - name: Scan
        id: scan
        run: |
          if [ -s previous.jsonl ]; then echo "baseline=true" >> "$GITHUB_OUTPUT"; else : > previous.jsonl; fi
          set +e
          subenum -w wordlist.txt -format jsonl -diff previous.jsonl \
            -o current.jsonl -stats run.json "$TARGET" > changes.jsonl
          code=$?
          echo "code=$code" >> "$GITHUB_OUTPUT"
          echo "verdict=$(jq -r .verdict run.json)" >> "$GITHUB_OUTPUT"
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

      # Only a complete run becomes the next baseline: a degraded one may be
      # missing names whose lookups failed.
      - name: Keep the current results for next time
        if: steps.scan.outputs.verdict == 'complete'
        run: mv current.jsonl previous.jsonl

      - if: steps.scan.outputs.verdict == 'complete'
        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: subenum-results
          path: |
            previous.jsonl
            run.json
          retention-days: 90
```
{% endraw %}

A failed, degraded or unreliable scan uploads nothing, so the next run still
compares against the last complete baseline. To keep a baseline longer than 90 days,
commit `previous.jsonl` to a branch or store it in object storage instead.

## Takeover candidates in code scanning

Add `-type A,AAAA,CNAME -sarif takeovers.sarif` to the scan and upload the file
after it, and every dangling or takeover-prone CNAME becomes an alert in the
repository's Security tab, where it can be triaged and dismissed. Alerts are
fingerprinted per name, so a candidate seen every week stays one alert. With
`NS`{% include unreleased.html value="type=NS" %} in the list as well
(`-type A,AAAA,CNAME,NS`), so does every delegation to a name server that does
not exist (`dangling-ns`); a release that does not have `NS` yet rejects it, so
add it only once the pinned `SUBENUM_VERSION` does. The job needs
`security-events: write`:

```yaml
      - name: Upload takeover candidates
        if: always() && hashFiles('takeovers.sarif') != ''
        uses: github/codeql-action/upload-sarif@33d7b85da1a04171e211befe2c739303b9a4c066 # v4
        with:
          sarif_file: takeovers.sarif
          category: subenum
```

A webhook works the same way as the issue step: post `changes.jsonl` (or the
`added` names) to Slack, Teams or your alerting endpoint.
