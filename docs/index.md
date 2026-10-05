---
layout: default
title: Home
---

> **Authorized use only.** Only scan domains you own or have explicit written permission to test.

## What it does

subenum brute-forces subdomains by resolving a wordlist against a target domain with a concurrent worker pool. Resolved names stream to stdout, pipe-clean; progress, diagnostics and the per-query breakdown go to stderr. It ships with a 5,000-entry wordlist, so `subenum yourdomain.com` works out of the box.

<div class="screenshot-wrap">
  <figure>
    <img src="assets/tui-form.png" alt="subenum TUI - Configure Scan">
    <figcaption>Interactive TUI: <code>subenum -tui</code></figcaption>
  </figure>
</div>

## Why subenum

Tools like [puredns](https://github.com/d3mondev/puredns), [shuffledns](https://github.com/projectdiscovery/shuffledns) and [dnsx](https://github.com/projectdiscovery/dnsx) are built for raw mass resolution, and [subfinder](https://github.com/projectdiscovery/subfinder) covers passive sources. subenum is a single static binary focused on telling you how much to trust the result:

- **It accounts for every query.** Each lookup is classified as resolved, nxdomain, timeout, refused or other. `-stats` writes a versioned JSON report with a `complete` / `degraded` / `unreliable` verdict that CI can gate on, and the scan stops when more than 20% of queries fail instead of returning a quietly incomplete list.
- **It handles wildcards,** including CDN and load-balancer pools that rotate their answers. Inconclusive wildcard checks are reported, never read as "no wildcard".
- **Its resolver pool cannot lie to you.** `-r resolvers.txt` spreads queries over many resolvers and benches failing ones, and every hit is re-validated against your trusted resolver before it is reported.
- **Its rate limit is real.** `-rate` caps DNS packets on the wire, including retries and every record type, so it can be quoted in rules of engagement.
- **It respects scope.** `-exclude` keeps out-of-scope names from ever being queried.
- **It can be taught and demoed.** `-simulate` produces marked, reproducible output with zero network traffic, and `-tui` gives a form-driven interface.

## Features

<dl class="feature-list">
  <div>
    <dt>Run-quality report</dt>
    <dd><code>-stats run.json</code> (or the last line of <code>-format jsonl</code>): outcomes per target, queries sent, achieved rate, and a verdict with its reason.</dd>
  </div>
  <div>
    <dt>Resolver pool</dt>
    <dd><code>-r</code> rotates over healthy resolvers, benches failing ones, and re-validates every hit against <code>-dns-server</code>.</dd>
  </div>
  <div>
    <dt>Wildcard filtering</dt>
    <dd>Fingerprints the wildcard before scanning, learns rotating pools, and re-checks near misses. Recursive scans skip wildcard branches.</dd>
  </div>
  <div>
    <dt>Takeover hints</dt>
    <dd>CNAMEs that dangle or point at takeover-prone services (S3, GitHub Pages, Heroku, Azure, ...) are flagged. DNS-only hints to verify by hand.</dd>
  </div>
  <div>
    <dt>Monitoring</dt>
    <dd><code>-diff previous.jsonl</code> prints only names added or removed since the last run and exits 4 on changes. See <a href="monitoring.html">Monitoring</a>.</dd>
  </div>
  <div>
    <dt>Scope control</dt>
    <dd><code>-exclude</code> and <code>-exclude-file</code> take exact names and <code>*.parent</code> patterns; excluded names are never queried.</dd>
  </div>
  <div>
    <dt>Output formats</dt>
    <dd><code>text</code>, <code>json</code>, <code>jsonl</code> or <code>csv</code> via <code>-format</code>, to stdout and <code>-o</code>. Results files are replaced atomically.</dd>
  </div>
  <div>
    <dt>Many targets</dt>
    <dd><code>-dL domains.txt</code> scans each domain as its own scan, with a per-target status and exit code 3 for partial failure.</dd>
  </div>
  <div>
    <dt>Simulation and TUI</dt>
    <dd><code>-simulate</code> for demos and tests with zero network I/O; <code>-tui</code> for a form-driven interface.</dd>
  </div>
</dl>

## Quick Start

**Install:**

```bash
go install github.com/TMHSDigital/subenum@latest
subenum yourdomain.com
```

Or download a [release binary](https://github.com/TMHSDigital/subenum/releases/latest), or run the container image:

```bash
docker run --rm ghcr.io/tmhsdigital/subenum:latest -simulate -w /home/nonroot/examples/sample_wordlist.txt example.com
docker run --rm ghcr.io/tmhsdigital/subenum:latest -w /home/nonroot/examples/sample_wordlist.txt yourdomain.com
```

**Try it with no network at all:**

```bash
subenum -simulate -hit-rate 20 example.com
subenum -tui
```

**A thorough, CI-friendly scan:**

```bash
subenum -w big-wordlist.txt -r resolvers.txt -rate 500 -type A,AAAA,CNAME \
  -format jsonl -o results.jsonl -stats run.json yourdomain.com
jq -e '.verdict == "complete"' run.json
```

## Flags

{% include flags.md %}

Exit codes: `0` success, `1` failure, `2` invalid arguments, `3` some `-dL` targets failed, `4` `-diff` found changes, `130` interrupted, `143` terminated.

## Documentation

<div class="doc-nav">
  <a href="ARCHITECTURE.html">Architecture</a>
  <a href="DEVELOPER_GUIDE.html">Developer Guide</a>
  <a href="docker.html">Docker</a>
  <a href="monitoring.html">Monitoring</a>
  <a href="CONTRIBUTING.html">Contributing</a>
  <a href="ROADMAP.html">Roadmap</a>
  <a href="https://github.com/TMHSDigital/subenum/blob/main/examples/advanced_usage.md">Advanced Usage</a>
  <a href="https://github.com/TMHSDigital/subenum/blob/main/CHANGELOG.md">Changelog</a>
</div>
