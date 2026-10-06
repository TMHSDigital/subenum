---
layout: default
title: Labs
---

# Labs: DNS enumeration without touching real infrastructure

These exercises teach subdomain enumeration on fictional zones. `-simulate-zone`
loads a scenario file and answers every query from a DNS server that subenum
runs on `127.0.0.1` for the length of the scan. **No DNS traffic leaves your
machine**, so labs are safe in a classroom, a CTF or an air-gapped VM.

Unlike `-simulate`, which invents results from a hit rate, a lab runs the real
resolver against the scenario. Wildcard detection, `-rate` pacing, retries, the
reliability guard and the run-quality report all behave exactly as they would
against a live zone, and the results are the same on every run.

## Setup

You need a subenum binary (see [Installation](https://github.com/TMHSDigital/subenum#installation))
and a copy of the repository for the scenario files. For a zero-install
classroom, [open the labs in GitHub Codespaces](https://codespaces.new/TMHSDigital/subenum?devcontainer_path=.devcontainer/labs/devcontainer.json&quickstart=1):
the container builds `./subenum`, opens this page and the first scenario, and
prints the lab 1 command.

Every lab scans `lab.example` with the short wordlist `examples/labs/words.txt`.
Run the commands from the repository root:

```bash
L=examples/labs
W="-w $L/words.txt"
```

Each lab ends with questions. The answers are folded underneath; try first.

## Lab 1: a first scan

```bash
subenum $W -simulate-zone $L/lab1-first-scan.zone -show-records lab.example
```

`-show-records` prints the records behind each name.

1. How many subdomains did the scan find?
2. Which host has an IPv6 address?
3. `shop` has the same address as `www`. Why?
4. The scenario file defines `blog`, but it is not in the results. Rerun with
   `-type A,AAAA,CNAME`. What is `blog`, and why did the default scan miss it?

<details markdown="1">
<summary>Answers</summary>

1. Five: `www`, `mail`, `vpn`, `jenkins` and `shop`.
2. `www` (`2001:db8::10`).
3. `shop` is a CNAME (an alias) for `www`. The resolver follows the alias and
   returns `www`'s addresses. The CNAME run shows `CNAME=www.lab.example`.
4. `blog` is a CNAME to `ghost-lab.example.net`, a host that does not exist.
   The default lookups (A and AAAA) find no address, so the name looks empty.
   With CNAME lookups, subenum shows the alias and flags it
   `TAKEOVER?=dangling`: the alias points at a name nobody has registered. If
   that were a cloud service, whoever claimed the name would control
   `blog.lab.example`. This is how subdomain takeovers start. See
   [takeover hints](https://github.com/TMHSDigital/subenum#subdomain-takeover-hints)
   in the README.

</details>

## Lab 2: spot the wildcard

```bash
subenum $W -simulate-zone $L/lab2-wildcard.zone lab.example
```

1. What does subenum report, and why does it refuse to continue?
2. Rerun with `-force`. Which names are reported now, and how does subenum tell
   them apart from the wildcard?

<details markdown="1">
<summary>Answers</summary>

1. "Wildcard DNS detected": the zone has a `*` record, so every name, even a
   random one, resolves to `192.0.2.250`. Without filtering, every word in the
   list would be reported as a "finding".
2. `www`, `portal` and `intranet`. Before scanning, subenum queries several
   random names to fingerprint the wildcard's answer. With `-force` it then
   drops every result that matches that fingerprint; these three have their
   own addresses, so they are real hosts. The `wildcard-filtered` line counts
   the rest.

</details>

## Lab 3: rate limits

This resolver answers REFUSED once it gets more than 40 queries in a second,
as many public and corporate resolvers do.

```bash
subenum $W -simulate-zone $L/lab3-rate-limit.zone -stats lab3.json lab.example
subenum $W -simulate-zone $L/lab3-rate-limit.zone -stats lab3-paced.json -rate 30 lab.example
```

1. Compare the `refused` counts of the two runs.
2. Open both `-stats` reports. What is each run's `verdict`?
3. Why can the first run still list some real names, and why should you not
   trust it anyway?

<details markdown="1">
<summary>Answers</summary>

1. The first run bursts with 100 workers and most of its lookups are refused.
   The paced run (`-rate 30`, under the resolver's 40-per-second limit) has
   none.
2. `unreliable` for the burst, `complete` for the paced run.
3. The first queries arrived before the limit kicked in, so whatever they
   found is real. But a REFUSED name was never actually checked: it might
   exist. A run with many refusals says nothing about the names it missed,
   which is why the report calls it unreliable. Slower is faster here.

</details>

## Lab 4: recursive discovery

```bash
subenum $W -simulate-zone $L/lab4-recursive.zone lab.example
subenum $W -simulate-zone $L/lab4-recursive.zone -recursive -depth 3 lab.example
```

1. How many names does the flat scan find? How many does the recursive scan
   find?
2. Which name needed `-depth 3`?
3. Try the recursive scan with the bundled 5,000-word list (drop `$W`). What
   happens, and why?

<details markdown="1">
<summary>Answers</summary>

1. Three (`www`, `dev`, `corp`) against eight. Recursion takes every name it
   finds and enumerates the wordlist under it, which turns up `api.dev`,
   `git.dev`, `staging.dev` and `vpn.corp`, then `admin.staging.dev`.
2. `admin.staging.dev`, three labels below `lab.example`.
3. subenum refuses to start: with 5,000 words, depth 3 could mean over 100
   billion queries. Recursion multiplies the wordlist at every level, so it
   asks you to set `-max-queries` (or `-force`) first. Against a real target,
   that guard is what keeps a scan from becoming a flood.

</details>

## Lab 5: when lookups fail

```bash
subenum $W -simulate-zone $L/lab5-failures.zone -timeout 300 -stats lab5.json lab.example
```

1. Which outcome lines in the breakdown are non-zero besides `resolved` and
   `nxdomain`?
2. What is the run's `verdict` in `lab5.json`, and what does it mean for the
   names that failed?

<details markdown="1">
<summary>Answers</summary>

1. `timeout` (`legacy` and `old` never answer), `refused` (`beta`) and `other`
   (`backup` answers SERVFAIL).
2. `degraded`: the scan finished, but some names could not be checked. A
   failed lookup is not "does not exist". Those names need a retry
   (`-attempts`) or a different resolver before you can rule them out.

</details>

## Writing your own scenario

A scenario is a plain text file. Names are relative to the domain you scan,
and `#` starts a comment:

```text
$DELAY 20ms            # every answer waits this long
$REFUSE-ABOVE 50       # answer REFUSED past 50 queries a second
@        A        192.0.2.1             # the scanned domain itself
www      A        192.0.2.10
www      AAAA     2001:db8::10
shop     CNAME    www                   # relative target
blog     CNAME    ghost.example.net.    # absolute target (trailing dot)
*.dev    A        192.0.2.99            # wildcard under dev
slow     TIMEOUT                        # never answered
broken   SERVFAIL                       # also: REFUSED, NXDOMAIN
```

Names the file does not define are NXDOMAIN. The scenario is the whole world
during a lab, so names outside the scanned domain (such as an external CNAME
target) are NXDOMAIN too. Use the
documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
`2001:db8::/32`) and reserved names such as `lab.example`, so nothing in a
lab points at a real host.

Scenarios work with every other flag, such as `-dL` (each listed domain gets
the same zone), `-permute`, `-diff`, `-format json` and `-stats`, which
records the scenario file under `zone`. `-simulate-zone` cannot be combined
with `-simulate`, `-dns-server` or `-r`, whether they come from the command
line, a `SUBENUM_*` variable or the config file: a lab run refuses to start
rather than send a query off the machine.
