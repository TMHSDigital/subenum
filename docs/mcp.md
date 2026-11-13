---
layout: default
title: AI agents (MCP)
---

# AI agents (MCP)

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
refused rather than ignored.

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
every lookup ended, any notices, and the scan's verdict:

| Verdict | Meaning for the agent |
| :--- | :--- |
| `complete` | A name missing from the results most likely does not exist. |
| `degraded` | Some names were not tested or got no answer, so a missing name may still exist. |
| `unreliable` | Too many lookups failed: a missing name means nothing. |
| `not_run` | The scan stopped before testing any name, for example on a wildcard zone; `error` says why. |

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

The caps cannot be turned off: `-rate`, `-max-queries` and `-max-duration` must
be positive.

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
