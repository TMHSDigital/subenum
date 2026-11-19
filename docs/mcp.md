---
layout: default
title: AI agents (MCP)
---

# AI agents (MCP){% include unreleased.html command="mcp" %}

{% if site.data.unreleased.commands contains "mcp" -%}
<p class="unreleased-note"><code>subenum mcp</code> is on <code>main</code> but not in {{ site.github.latest_release.tag_name | default: "the latest release" }} yet, so a release binary treats <code>mcp</code> as a domain. To use it now, build from main: <code>go install github.com/TMHSDigital/subenum@main</code>.</p>
{%- endif %}

`subenum mcp` serves subdomain enumeration to AI agents and assistants over the
[Model Context Protocol](https://modelcontextprotocol.io), on standard input and
output. The operator who starts the server decides everything that matters for
safety. The model chooses only what to scan within those limits.

| You decide, on the command line | The model decides, per call |
| :--- | :--- |
| Which domains a live scan may target (`-allow`) | A domain within the allow-list |
| The resolver (`-dns-server`) and the lookup timeout (`-timeout`) | The words to try, and the record types |
| The query rate (`-rate`) | A smaller `max_queries`, never a larger one, and an `offset` into the word list |
| The most names one call may test (`-max-queries`) and its time budget (`-max-duration`) | For lab scans only: the scenario, a rate, and `force` |

Tool calls run one at a time, so a model cannot multiply the budget by calling
in parallel; at most 8 may be running or waiting at once, and the next is
refused with an invalid-request error until one finishes. Arguments the tools do not define (a resolver, say) are
refused rather than ignored. A client that sends a `progressToken` with a
`scan` or `lab_scan` call gets a progress notification about once a second
(`312/1000 tested, 4 found`), and can cancel the call at any time.

## Tools

**`lab_scan`** scans `lab.example` in one of the [lab scenarios](labs.html),
compiled into the binary and answered by a DNS server on the loopback
interface. No traffic leaves the machine, so it is always offered and always
safe. It is the place for an agent to learn what wildcards, rate limits and a
failing resolver do to a scan. Its `scenario` argument describes each
scenario, from the opening comment of its zone file, so an agent can pick one
and explain it.

**`scan`** enumerates a real domain through the operator's resolver. It is
offered only when `-allow` names at least one domain, and it refuses any domain
that is not an allowed one or a subdomain of one. Only allow domains you own or
have permission to test.

**`explain_stats`** explains a run-quality report from the command line: pass
the contents of a `-stats` file, or `-format jsonl` output, which ends with the
same summary. It says how far the results can be trusted, why, and what to
change next time.

**`diff`** compares two result sets without sending a DNS query, as
[`subenum diff -records`](monitoring.html) does. `previous` and `current` each
take a `scan` or `lab_scan` report (or its `results` array) or the contents of
a results file in any output format; `types` limits which record types count
for a change. It returns `added`, `missing` and `changed` names with their
records (and `previous_records` for a changed name), as `structuredContent`
too. When either side has a CNAME, only the CNAME targets are compared, so CDN
address rotation is not reported as a change. Names in `previous` but not in
`current` are called missing, not removed: nothing was looked up, so they are
unverified. A text-format result set has no records, so `records_compared` is
then false and `changed` is empty. Like `explain_stats`, it takes contents,
not paths, and one call is bounded by the server's 16 MiB message limit.

`lab_scan` and `scan` return JSON with the names found and their records, how
every lookup ended, any notices, and the scan's verdict. Both declare it as an
`outputSchema`, and send it as `structuredContent` as well as text, so a client
can read the report as data without parsing it:

| Verdict | Meaning for the agent |
| :--- | :--- |
| `complete` | A name missing from the results most likely does not exist. |
| `degraded` | Some names were not tested or got no answer, so a missing name may still exist. |
| `unreliable` | Too many lookups failed, or the scan stopped early with an error (see `error`): a missing name means nothing. |
| `not_run` | The scan stopped before testing any name, for example on a wildcard zone; `error` says why. |

When a verdict is not `complete`, the agent can act on it within the
operator's limits: `retry_inconclusive` looks up the names that got no answer
once more at the end, `auto_rate` slows down while lookups fail instead of
giving up, `exclude` keeps names or branches (`*.corp.example.com`) out of the
scan, and `depth` (up to 3) enumerates again under the names found. The report
counts `retried`, `recovered`, `rate_backoffs` and `excluded`. Every one of
these stays within `max_queries` and `-max-duration`.

`permute`, on `scan` and `lab_scan`, adds a second pass after the scan, as the
command line's `-permute` does: it tests variants of the names found (`api`
suggests `api-dev`, `dev-api`, `api2`) that the scan did not already test,
within what the scan left of `max_queries` and `-max-duration`. Its finds join
`results`, and the report's `permutation` gives its `candidates`, `tested`,
`found`, `skipped_by_cap` and its own `verdict` and `reason`. A scan that
spent the whole budget leaves the pass `degraded` with every variant skipped.

## Running it

```bash
subenum mcp                                   # lab_scan, explain_stats and diff only
subenum mcp -allow example.com,example.org    # adds scan, for these domains
```

| Flag | Default | Meaning |
| :--- | :--- | :--- |
| `-allow` | none | Comma-separated domains `scan` may enumerate, each with its subdomains |
| `-dns-server` | `8.8.8.8:53` | Resolver for live scans: `ip:port`, `tls://host` or `https://host/path` |
| `-rate` | 20 | DNS queries per second for live scans |
| `-max-queries` | 1000 | Most candidate names one call may test |
| `-max-duration` | 2m | Longest one call may scan |
| `-timeout` | 1000 | Live-scan lookup timeout in milliseconds |
| `-sources` | none | Passive sources (`ct`, `wayback`) a `scan` call may ask for |
| `-axfr` | off | Let a `scan` call ask the domain's name servers for a zone transfer (`zone_transfer`) |
| `-max-calls` | 100 | Most `scan` calls one session may make; with `-max-queries` it caps the session's live lookups. A call refused for its arguments (`not_run` before any query) does not count |

Passive sources are off unless you enable them, because they send the domain
to third parties (crt.sh, the Wayback Machine). With `-sources ct,wayback`,
`scan` gains a `sources` argument: the names a source proposes join the words
after dedupe, count against `max_queries`, and are each verified by a lookup.
The report lists each source with the number of names it proposed, or the
error it hit; a failed source does not stop the scan.

Zone transfers are off unless you start the server with `-axfr`, because
their queries go to the target's own name servers (about four per server)
and are not paced by `-rate`. With it, `scan` gains a `zone_transfer`
argument that does what the command line's `-axfr` does before the scan:
the names a transfer gives are verified by a lookup like a source's, and the
report's `zone_transfer` lists the name servers that `allowed` one (anyone
can then list the zone, a finding in itself) and the zone's `denial`
(`nsec` means it can be walked). Name servers under `exclude` are not asked.
Without `-axfr`, a call that sets it is refused. `lab_scan` has no
`zone_transfer` yet; the command line practises transfers in Lab 7.

The caps cannot be turned off: `-rate`, `-max-queries`, `-max-duration`,
`-timeout` and `-max-calls` must be positive. A session is one run of the
server: it ends when the client closes it. Calls the client sent before
closing standard input are still answered, but once the client stops
reading the replies, the running call is cancelled and queued ones never
start.

`subenum mcp` takes its settings from these flags only. The `SUBENUM_*`
environment variables and the config file that set defaults for scans do not
apply to it, so `SUBENUM_DNS_SERVER` does not change the agent's resolver: pass
`-dns-server`.

A `scan` call without `words` uses the bundled list of 5,000 common labels, but
tests no more than `-max-queries` of them (1,000 by default), so its verdict is
`degraded` with the rest counted as skipped. The report then carries a
`next_offset`, and its `reason` says to call again with it: `scan` and
`lab_scan` take an `offset` argument that skips that many candidates at the
start of the word list (after dedupe), so the agent can work through the
whole list in five calls (at the default `-max-queries` of 1000) with the same `words`. Every call stays within
`-max-queries`, `-max-duration` and `-max-calls`. `next_offset` is given only
when `max_queries` was what stopped the scan among the words: a call the time
budget ended has gaps among the names it tested, so repeat that one with a
smaller `max_queries`. Names from `sources` come after the words and are not
counted by `offset`. To cover the list in one call instead, raise
`-max-queries`.

In a container, keep standard input open with `-i`, since the protocol runs over
it:

```bash
docker run -i --rm ghcr.io/tmhsdigital/subenum:latest mcp -allow example.com
```

Most MCP clients take a command and its arguments. For example, in a client
configuration file:

```json
{
  "mcpServers": {
    "subenum": {
      "command": "subenum",
      "args": ["mcp", "-allow", "example.com", "-rate", "20"]
    }
  }
}
```

With Claude Code: `claude mcp add subenum -- subenum mcp -allow example.com`.

The server speaks MCP revisions 2025-06-18, 2025-03-26 and 2024-11-05, offers
tools only, and writes nothing but protocol messages to standard output.
