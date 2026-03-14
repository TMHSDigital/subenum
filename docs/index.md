---
layout: default
title: Home
---

> **Authorized use only.** Only scan domains you own or have explicit written permission to test.

---

## What it does

subenum brute-forces subdomains by resolving a wordlist against a target domain using a concurrent worker pool. Results stream to stdout — pipe-clean, no noise. Everything else (progress, diagnostics, errors) goes to stderr.

<div class="screenshot-wrap">
  <figure>
    <img src="assets/tui-form.png" alt="subenum TUI — Configure Scan">
    <figcaption>Interactive TUI — launch with <code>./subenum -tui</code> or <code>make tui</code></figcaption>
  </figure>
</div>

---

## Features

<div class="feature-grid">
  <div class="feature-card">
    <strong>Worker Pool</strong>
    <span>Spawn N goroutines for parallel DNS resolution with a configurable concurrency ceiling.</span>
  </div>
  <div class="feature-card">
    <strong>Wildcard Detection</strong>
    <span>Double-probe check before scanning; exits early unless <code>-force</code> is set.</span>
  </div>
  <div class="feature-card">
    <strong>Interactive TUI</strong>
    <span>Form-based config and live-scrolling results via <code>-tui</code>. Session values persisted to <code>~/.config/subenum/last.json</code>.</span>
  </div>
  <div class="feature-card">
    <strong>Simulation Mode</strong>
    <span>Generate synthetic DNS results at a configurable hit rate — zero network I/O. Safe for demos and testing.</span>
  </div>
  <div class="feature-card">
    <strong>Pipe-Friendly Output</strong>
    <span>Resolved subdomains stream to stdout only. Progress and diagnostics go to stderr. Compose freely with other tools.</span>
  </div>
  <div class="feature-card">
    <strong>Graceful Shutdown</strong>
    <span>Trap SIGINT/SIGTERM, drain in-flight workers, flush partial results before exit.</span>
  </div>
  <div class="feature-card">
    <strong>Retry with Backoff</strong>
    <span>Configurable DNS resolution attempts per subdomain with linear backoff for flaky networks.</span>
  </div>
  <div class="feature-card">
    <strong>Input Validation</strong>
    <span>RFC-compliant domain syntax and strict <code>ip:port</code> format enforcement on startup.</span>
  </div>
</div>

---

## Quick Start

**Build from source:**

```bash
git clone https://github.com/TMHSDigital/subenum.git
cd subenum
go build -buildvcs=false -o subenum
```

**Run a scan:**

```bash
./subenum -w wordlist.txt example.com
```

**Launch the TUI:**

```bash
./subenum -tui
```

**Simulation (zero network I/O):**

```bash
./subenum -simulate -hit-rate 20 -w examples/sample_wordlist.txt example.com
```

**Docker:**

```bash
docker build -t subenum .
docker run --rm -v $(pwd)/data:/data subenum -w /data/wordlist.txt example.com
```

---

<div style="text-align:center">

## Documentation

</div>

<div class="doc-nav">
  <a href="ARCHITECTURE.html">Architecture</a>
  <a href="DEVELOPER_GUIDE.html">Developer Guide</a>
  <a href="docker.html">Docker</a>
  <a href="CONTRIBUTING.html">Contributing</a>
  <a href="https://github.com/TMHSDigital/subenum/blob/main/examples/advanced_usage.md">Advanced Usage</a>
  <a href="https://github.com/TMHSDigital/subenum/blob/main/CHANGELOG.md">Changelog</a>
</div>
