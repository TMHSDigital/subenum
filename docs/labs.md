---
layout: default
title: Labs
numbered: false
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

You need a subenum binary (see [Installation](https://github.com/TMHSDigital/subenum#installation)).
The scenarios and their wordlist are built into it, so the labs run from any
directory: `-simulate-zone lab1` (or `lab1-first-scan`) picks the built-in
scenario, and without `-w` the scan uses the labs' short wordlist. For a
zero-install classroom, [open the labs in GitHub Codespaces](https://codespaces.new/TMHSDigital/subenum?devcontainer_path=.devcontainer/labs/devcontainer.json&quickstart=1):
the container builds `./subenum`, opens this page and the first scenario, and
prints the lab 1 command.

Every lab scans `lab.example`. To edit a scenario or write your own, copy one
from [`examples/labs`](https://github.com/TMHSDigital/subenum/tree/main/examples/labs)
and pass its path instead, for example `-simulate-zone ./my-lab.zone`; a path
uses the bundled 5,000-word list unless you add `-w`.

Labs run from the command line. Combining `-tui` with an active `-simulate-zone`
setting (including `SUBENUM_SIMULATE_ZONE` or a config-file value) exits with
usage error 2 before the interface opens. Remove `-tui` to run the lab.

Each lab ends with questions. The answers are folded underneath; try first.

## Lab 1: a first scan

```bash
subenum -simulate-zone lab1 -show-records lab.example
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
subenum -simulate-zone lab2 lab.example
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
subenum -simulate-zone lab3 -stats lab3.json lab.example
subenum -simulate-zone lab3 -stats lab3-paced.json -rate 30 lab.example
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
subenum -simulate-zone lab4 lab.example
subenum -simulate-zone lab4 -recursive -depth 3 lab.example
```

1. How many names does the flat scan find? How many does the recursive scan
   find?
2. Which name needed `-depth 3`?
3. Try the recursive scan with the bundled 5,000-word list (add `-w ""`). What
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
   that guard is what keeps a scan from becoming a flood. A shorter list for
   the deeper levels also keeps it small: `-recursive-w` names the labels
   tried under each name found, so `-w` with 5,000 words and `-recursive-w`
   with 100 cost 5,000 queries for depth 1 and 100 for each name found.

</details>

## Lab 5: when lookups fail

```bash
subenum -simulate-zone lab5 -timeout 300 -stats lab5.json lab.example
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

## Lab 6: IPv6-only services

```bash
subenum -simulate-zone lab6 -show-records lab.example
subenum -simulate-zone lab6 -type A -show-records lab.example
subenum -simulate-zone lab6 -type AAAA -show-records lab.example
```

1. Which three names does the default scan find, and which address families
   does each have?
2. Which name disappears with `-type A`? Does that mean the service is absent?
3. Which name disappears with `-type AAAA`? Why does the default scan find both?

<details markdown="1">
<summary>Answers</summary>

1. `www` has both `A=192.0.2.10` and `AAAA=2001:db8::10`; `api` has only
   `AAAA=2001:db8::20`; `legacy` has only `A=192.0.2.30`.
2. `api` disappears. It exists but has no IPv4 address: an A-only lookup
   cannot discover an IPv6-only service.
3. `legacy` disappears because it has no IPv6 address. The default types are
   `A,AAAA`, and a record of either type is enough to report a name. Querying
   both families does not require the machine to have IPv6 connectivity:
   this lab's DNS server still answers on IPv4 loopback (`127.0.0.1`).

</details>

## Lab 7: a zone transfer{% include unreleased.html value="simulate-zone=lab7" %}

```bash
subenum -simulate-zone lab7 -format jsonl lab.example
subenum -simulate-zone lab7 -axfr -format jsonl lab.example
```

The lab's name server hands its whole zone to anyone who asks, the
misconfiguration `-axfr` looks for. In lab mode the transfer goes to the lab
server, never to the name server's real address.

1. Which names does the second run find that the first does not, and what is
   their `sources`?
2. What does the second run print on stderr about the name server?
3. Copy `examples/labs/lab7-zone-transfer.zone`, delete its `$TRANSFER allow`
   line and run the copy with `-axfr -v`. What changes?

<details markdown="1">
<summary>Answers</summary>

1. `billing-legacy`, `k8s-ingress-eu2` and `ns1`: no wordlist holds them. Their
   `sources` is `["axfr"]`, while `www`, `mail` and `vpn` say
   `["wordlist", "axfr"]`. Every transferred name is still looked up, so a
   stale entry would not be reported.
2. That `ns1.lab.example` allowed a transfer of `lab.example` and that anyone
   can list the zone: a finding to report in itself. `-stats` names the
   server under `axfr_allowed`.
3. The server refuses, as most do. The scan is the wordlist's alone, and `-v`
   says that no name server allowed a transfer.

</details>

## Lab 8: an NSEC walk{% include unreleased.html value="simulate-zone=lab8" %}

```bash
subenum -simulate-zone lab8 -format jsonl lab.example
subenum -simulate-zone lab8 -nsec-walk -format jsonl lab.example
```

The zone is signed with plain DNSSEC NSEC and refuses transfers. Every
answer that says a name does not exist also names the next name that does,
so `-nsec-walk` can list the whole zone, one query per name. In lab mode
the walk goes to the lab server.

1. Which names does the second run find that the first does not, and what is
   their `sources`?
2. How many queries did the walk take, and why that many?
3. Copy `examples/labs/lab8-nsec-walk.zone`, change `$DNSSEC nsec` to
   `$DNSSEC nsec3` and run the copy with `-nsec-walk`. What changes?

<details markdown="1">
<summary>Answers</summary>

1. `payroll-archive`, `qa.build-farm` and `ns1`: no wordlist holds them. Their
   `sources` is `["nsec"]`, while `www`, `mail` and `vpn` say
   `["wordlist", "nsec"]`. Every walked name is still looked up.
2. Seven: one per name in the chain, the apex included, until the last
   record leads back to the apex. `-stats` counts the names under
   `nsec_names`.
3. NSEC3 records hold hashes of names, not names, so there is nothing to
   follow: subenum says it is not walking the zone and why, and the scan is
   the wordlist's alone.

</details>

## Lab 9: a dangling delegation{% include unreleased.html value="simulate-zone=lab9" %}

```bash
subenum -simulate-zone lab9 -format jsonl lab.example
subenum -simulate-zone lab9 -type A,NS -format jsonl -stats run.json lab.example
```

`legacy` is a subzone delegated to two name servers that no longer exist, so
the lab's resolver, which cannot reach either, answers SERVFAIL for it, as a
real one would. Whoever registers `legacy-dns.example` would answer for every
name under `legacy`. `staging` is delegated to a name server that still
answers. With `NS` in `-type`, subenum asks the zone's own name server about a
name that ends SERVFAIL, without asking it to recurse, and gets the
delegation back as a referral. In lab mode that query goes to the lab
server.

1. How does `legacy` end in the first run, and in the second?
2. What does the second run's report say about the extra queries?
3. Why is `staging` not marked?

<details markdown="1">
<summary>Answers</summary>

1. The first run counts it under `other` (inconclusive): without `NS` nothing
   asks the zone. The second reports it with its two NS records and
   `"takeover_candidate":"dangling-ns"`, because both name servers are
   NXDOMAIN.
2. `parent_checks` is 1 (one name was asked about) and `parent_queries` is 1;
   `queries_sent` includes it. The query takes a `-rate` slot like any other.
3. Its name server, `ns1.lab.example`, exists, so a resolver gets its NS
   records directly and there is nothing to take over.

</details>

## Writing your own scenario

A scenario is a plain text file. Names are relative to the domain you scan,
and `#` starts a comment:

```text
$DELAY 20ms            # every answer waits this long
$REFUSE-ABOVE 50       # answer REFUSED past 50 queries a second
$TRANSFER allow        # answer a zone transfer (-axfr); the default is refuse
$DNSSEC nsec           # prove absent names with NSEC (-nsec-walk), or nsec3; the default is none
@        A        192.0.2.1             # the scanned domain itself
www      A        192.0.2.10
www      AAAA     2001:db8::10
shop     CNAME    www                   # relative target
blog     CNAME    ghost.example.net.    # absolute target (trailing dot)
*.dev    A        192.0.2.99            # wildcard under dev
mail     MX       10 mx1                # preference and host (relative or absolute)
@        TXT      "v=spf1 -all"         # the rest of the line; quotes optional
@        HTTPS    1 . alpn=h2,h3 port=443  # priority, host ("." or a name), alpn and port (-type HTTPS)
cdn      HTTPS    0 edge.example.net.   # AliasMode: points cdn at another host, like a CNAME
sub      NS       ns1.gone.example.     # a delegated subzone (scan with -type NS)
slow     TIMEOUT                        # never answered
broken   SERVFAIL                       # also: REFUSED, NXDOMAIN
192.0.2.10 PTR    host-12.dc1           # reverse DNS of an address (-ptr); relative or absolute host
```

Start a scenario in `examples/labs` with a comment saying what it teaches
(`# Lab 6: <title>. <what to look for>`): `subenum mcp` shows that comment,
without the lab number and any indented command line, to agents choosing a
scenario.

Names the file does not define are NXDOMAIN. The scenario is the whole world
during a lab, so names outside the scanned domain (such as an external CNAME
target) are NXDOMAIN too. A CNAME to a name in the scenario is followed as a
recursive resolver follows it, through further CNAMEs (up to 8) and
wildcards, so `a CNAME b`, `b CNAME www` answers with `www`'s addresses. An
AAAA value must be a real IPv6 address: an IPv4-mapped one such as
`::ffff:192.0.2.1` is rejected. An answer too big for the client's UDP
buffer comes back truncated, so the client asks again over TCP. Use the
documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
`2001:db8::/32`) and reserved names such as `lab.example`, so nothing in a
lab points at a real host.

Scenarios work with the other flags, such as `-dL` (each listed domain gets
the same zone), `-permute`, `-diff`, `-format json` and `-stats`, which
records the scenario file under `zone`. With `-axfr` or `-nsec-walk`, the
transfer, the DNSSEC probe and the walk go to the lab server, whatever
address the scenario gives its name servers. With `$DNSSEC nsec`, an answer
for a name the file does not define carries the NSEC record that covers it,
from a chain of the apex, the defined names (not failing ones) and the
wildcards. A delegation none of whose name servers has an address in the
scenario (such as `sub` above) answers SERVFAIL for itself and every name
under it, as a resolver that cannot reach them does, and a query that does
not ask for recursion gets a referral to them, as from the parent zone's
server; a delegation with one name server that answers is served from the
file. `-simulate-zone` cannot be combined
with `-simulate`, `-dns-server`, `-r`, `-ct` or `-sources`, whether they
come from the command line, a `SUBENUM_*` variable or the config file: a lab run refuses to start
rather than send a query off the machine.
