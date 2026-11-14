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
| The query rate (`-rate`) | A smaller `max_queries`, never a larger one |
| The most names one call may test (`-max-queries`) and its time budget (`-max-duration`) | For lab scans only: the scenario, a rate, and `force` |

Tool calls run one at a time, so a model cannot multiply the budget by calling
in parallel, and arguments the tools do not define (a resolver, say) are
refused rather than ignored. A client that sends a `progressToken` with a
`scan` or `lab_scan` call gets a progress notification about once a second
(`312/1000 tested, 4 found`), and can cancel the call at any time.

## Tools

**`lab_scan`** scans `lab.example` in one of the [lab scenarios](labs.html),
compiled into the binary and answered by a DNS server on the loopback
interface. No traffic leaves the machine, so it is always offered and always
safe. It is the place for an agent to learn what wildcards, rate limits and a
failing resolver do to a scan.

**`scan`** enumerates a real domain through the operator's resolver. It is
offered only when `-allow` names at least one domain, and it refuses any domain
that is not an allowed one or a subdomain of one. Only allow domains you own or
have permission to test.

**`explain_stats`** explains a run-quality report from the command line: pass
the contents of a `-stats` file, or `-format jsonl` output, which ends with the
same summary. It says how far the results can be trusted, why, and what to
change next time.

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

## Running it

```bash
subenum mcp                                   # lab_scan and explain_stats only
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

Passive sources are off unless you enable them, because they send the domain
to third parties (crt.sh, the Wayback Machine). With `-sources ct,wayback`,
`scan` gains a `sources` argument: the names a source proposes join the words
after dedupe, count against `max_queries`, and are each verified by a lookup.
The report lists each source with the number of names it proposed, or the
error it hit; a failed source does not stop the scan.

The caps cannot be turned off: `-rate`, `-max-queries`, `-max-duration` and
`-timeout` must be positive.

`subenum mcp` takes its settings from these flags only. The `SUBENUM_*`
environment variables and the config file that set defaults for scans do not
apply to it, so `SUBENUM_DNS_SERVER` does not change the agent's resolver: pass
`-dns-server`.

A `scan` call without `words` uses the bundled list of 5,000 common labels, but
tests no more than `-max-queries` of them (1,000 by default), so its verdict is
`degraded` with the rest counted as skipped. Raise `-max-queries` to cover the
whole list, or have the agent pass a shorter `words` list.

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
