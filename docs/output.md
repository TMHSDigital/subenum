---
layout: default
title: Output fields
description: Every field of subenum's JSON, JSONL and CSV results and of the -stats run-quality report, with JSON Schema files.
---

# Output fields

This page lists every field subenum writes, so a script can read results without reading Go source. Fields are only ever added, never renamed or removed, so a reader must accept fields it does not know. The same rules are in two JSON Schema (2020-12) files:

- [`schemas/result.v1.json`](schemas/result.v1.json): one result, as in JSON and JSONL output.
- [`schemas/stats.v1.json`](schemas/stats.v1.json): the `-stats` report, also the last line of JSONL output.

A test fails when a field is added to the code but not to these files, so they stay current.

## Results: JSON and JSONL

`-format json` writes one array of results; `-format jsonl` writes one result per line, then the run-quality report as the last line (its `type` is `summary`). A field marked "when set" is left out otherwise.

| Field | Type | Present | Meaning |
|---|---|---|---|
| `subdomain` | string | always | The full name, lower case, without a trailing dot. |
| `records` | array of `{type, value}` | always | The name's records of the `-type` record types. Empty for a name `-diff` reports as removed. |
| `simulated` | boolean | when set | `true` on every result of a `-simulate` run. |
| `takeover_candidate` | string | when set | A DNS-only [takeover hint](https://github.com/TMHSDigital/subenum#subdomain-takeover-hints): `dangling`, `provider:<name>` or `dangling:<name>` for a CNAME, `dangling-ns` for a delegation, `dangling-srv` for a service whose target host does not exist. Needs `CNAME`, `NS` or `SRV` in `-type`. |
| `internal_address` | string | when set | The most notable non-public scope among the name's addresses: `loopback`, `unspecified`, `link-local`, `private` or `cgnat`. |
| `partial` | boolean | when set | `true` when a requested record type's lookup failed on every attempt while another type answered: `records` may lack that type. |
| `change` | string | with `-diff` | `added`, `removed`, or with `-diff-records` `changed`. `subenum diff` writes `missing` instead of `removed`, because it looks nothing up. |
| `previous_records` | array of `{type, value}` | when `change` is `changed` | The baseline's records of the name. |
| `permutation` | boolean | when set | `true` for a name the `-permute` pass found. |
| `sources` | array of strings | scan results | What proposed the name, in this order: `wordlist`, `ct`, `wayback`, `axfr`, `nsec`, `srv`; or `permute` alone for a `-permute` hit, `records` alone for a `-follow-records` hit, `ptr` alone for a `-ptr` hit. Not on removed names or in `subenum diff` output. |
| `target` | string | scan results | The scanned domain that found the name, which tells `-dL` results with nested targets apart. Not on removed names or in `subenum diff` output. |
| `first_seen` | string | real runs | When the name was first seen, as an RFC 3339 time in UTC: the earliest `first_seen` the `-diff` baseline gave it (JSON, JSONL or CSV), else this run's time. Never on `-simulate` or `-simulate-zone` runs, so seeded output stays reproducible. On a removed name, and in `subenum diff` output, it is copied from the file the name came from. |
| `last_seen` | string | real runs | When a run last found the name: this run's time, in RFC 3339 UTC. Copied as `first_seen` is on removed names and in `subenum diff` output. |

A run's results all carry the same time, taken when the run starts. Pass each run's JSONL or CSV file to the next run's `-diff` (as the [GitHub Action](monitoring.html) does with its baseline) and `first_seen` carries forward, so a takeover candidate or an internal address shows how long it has been there.

A record's `type` is `A`, `AAAA`, `CNAME`, `NS`, `MX`, `TXT` or `SRV`{% include unreleased.html value="type=SRV" %}. Its `value` is an address, a host name (`CNAME`, `NS`), `<preference> <host>` (`MX`), the text (`TXT`), with a backslash and non-printable bytes written as `\DDD`, or `<priority> <weight> <port> <target>` (`SRV`).

## Results: CSV

CSV has one row per record, so a name with three records has three rows, and a name without records (a removed one) has one row with empty `type` and `value`. The header names the columns; optional ones are added in this order:

| Column | Present | Meaning |
|---|---|---|
| `subdomain` | always | As in JSON. |
| `type` | always | The record type. |
| `value` | always | The record value. A value starting with `=`, `+`, `-`, `@`, a tab or a carriage return gets a leading `'`, so a spreadsheet does not read it as a formula. |
| `simulated` | `-simulate` | `true`. |
| `takeover_candidate` | `CNAME`, `NS` or `SRV` in `-type` | As in JSON; empty when there is no hint. |
| `change` | `-diff` | As in JSON. |
| `sources` | scan results | As in JSON, joined with `;`. |
| `target` | `-dL` | As in JSON. |
| `first_seen`, `last_seen` | real runs, and `subenum diff` of files that have them | As in JSON; empty where a name has none. |

## Text

Text output is one name per line. `-show-records` appends the records as ` TYPE=value`, and `-diff` prefixes each name with `+`, `-` or `~`. Text has no other fields; use JSONL or CSV to keep them.

## Run-quality report

`-stats <file>` writes the report as indented JSON, and `-format jsonl` writes it as the last line. `schema` is `1`; it rises only if a field is renamed, removed or changes meaning. A field marked "when set" is left out when it is `0`, empty or `false`.

### Top level

| Field | Type | Present | Meaning |
|---|---|---|---|
| `type` | string | always | Always `summary`. |
| `schema` | integer | always | `1`. |
| `tool` | string | always | `subenum`. |
| `version` | string | always | The version that wrote the report. |
| `started` | string | always | When the run started, RFC 3339. |
| `duration_ms` | integer | always | Run time in milliseconds. |
| `simulated` | boolean | always | `true` for a `-simulate` run. |
| `seed` | integer | `-simulate` | The simulation seed. |
| `resolver` | string | not with `-simulate` | The `-dns-server` (scheme and host only), the lab's local server under `-simulate-zone`, or with `-r` the trusted resolver hits were re-validated against. |
| `zone` | string | `-simulate-zone` | The lab scenario. |
| `transport` | string | not with `-simulate` | `udp` (with TCP fallback), `tls` or `https`. |
| `rate_limit` | integer | always | `-rate`; `0` is unlimited. |
| `queries_sent` | integer | always | Queries sent on the wire, every target, type, retry and probe included. |
| `achieved_qps` | number | always | `queries_sent` over the run time. |
| `verdict` | string | always | `complete`, `degraded` or `unreliable`: the worst target's. |
| `reason` | string | always | Why, in plain words. |
| `targets` | array | always | One entry per target, below. |
| `resolvers` | array | `-r` | Per pool resolver: `address`, `lookups`, `found`, `nxdomain`, `failed`, `benched`, `throttled`, `canaries`, `contradicted`, `flagged`. |
| `diff` | object | `-diff` | `previous` (the file), `added`, `removed`, and when set `changed`, `still_resolving`, `unverified`. `removed` stays `0` unless the run was complete. |

### Each target

| Field | Type | Present | Meaning |
|---|---|---|---|
| `domain` | string | always | The target. |
| `status` | string | always | `ok`, `failed`, `interrupted`, `skipped` (left out after an earlier target's reliability abort) or `not_run`. |
| `error` | string | when set | Why a failed target failed. |
| `processed`, `total` | integer | always | Candidates the main pass looked up, of how many. |
| `found` | integer | always | Names the main pass found. |
| `outcomes` | object | always | How each lookup ended: `resolved`, `nxdomain`, `timeout`, `refused`, `other`, `wildcard_filtered`, `excluded`. |
| `queries_sent` | integer | always | This target's queries, its `-permute` pass included. |
| `skipped_by_cap` | integer | always | Candidates a budget left untested. |
| `stopped_by` | string | when set | `queries` (`-max-queries`) or `duration` (`-max-duration`). |
| `takeover_candidates`, `internal_addresses` | integer | when set | Results with a takeover hint, or with a non-public address. |
| `retried`, `recovered` | integer | when set | `-retry-inconclusive`: names looked up again, and those that then answered. |
| `rate_backoffs`, `final_rate` | integer | when set | `-auto-rate`: times it halved the rate, and the rate it ended at. |
| `permutation` | object | `-permute` ran | `seeds`, `candidates`, `found`, and when set `processed`, `queries_sent`, `verdict`. |
| `sources` | array | `-ct`, `-sources` | Per source: `name` (`ct`, `wayback`), `names` added, `found`, and when set `error`, `truncated`. |
| `ct_names`, `ct_error` | integer, string | when set | Repeat the `ct` entry of `sources`. |
| `axfr_allowed`, `axfr_names`, `axfr_error`, `axfr_found` | array, integer, string, integer | when set | `-axfr`: servers that allowed a transfer, names it added, why none could be tried, results it proposed. |
| `nsec_names`, `nsec_found`, `nsec_stop` | integer, integer, string | when set | `-nsec-walk`: names the walk listed, results it proposed, and why it stopped before the end of the chain or did not run. |
| `parent_checks`, `parent_queries` | integer, integer | when set | `-type NS`: names that failed with SERVFAIL whose delegation was asked of the zone's own name servers, and the queries that took (the name server lookups included; `queries_sent` counts them too). A subzone whose every name server is gone is found this way and flagged `dangling-ns`. |
| `records_found` | integer | when set | `-follow-records`: results that a found name's `CNAME`, `MX` or `NS` record pointed at. |
| `ptr_addresses`, `ptr_queries`, `ptr_names`, `ptr_found` | integer | when set | `-ptr`: public addresses looked up, PTR queries sent (`queries_sent` includes them and the lookups of the names), names under the target the answers gave that were tested, and results they proposed. |
| `zone_denial` | string | when set | The DNSSEC probe of `-axfr` or `-nsec-walk`: `nsec` (anyone can list the zone), `nsec3` or `none`. |
| `pool_hits`, `confirmed`, `unconfirmed` | integer | when set | `-r`: pool hits, and how many the trusted resolver confirmed or denied. |
| `wildcard` | boolean | always | `true` when the target answers names that do not exist. |
| `wildcard_fingerprint` | array of `{type, value}` | when set | The wildcard's answers. |
| `verdict`, `reason` | string | always | The worse of the two passes'; `reason` starts with `permutation pass:` when that pass decided it. |
