---
layout: default
title: Go library
description: Embed subenum's enumeration engine in your own Go program with pkg/subenum.
---

# Go library

`pkg/subenum` embeds the same engine the command line runs, so a recon pipeline or a custom tool can use it without shelling out. Wildcard filtering, rate limiting, retries, takeover hints, the reliability guard and the per-outcome accounting are all the same code.

```bash
go get github.com/TMHSDigital/subenum/pkg/subenum
```

The package follows semantic versioning from v1.0.0. Until then it may change between minor releases, while the CLI stays stable. The full API reference, with runnable examples, is on [pkg.go.dev](https://pkg.go.dev/github.com/TMHSDigital/subenum/pkg/subenum).

## Scan: a finished run

`Scan` runs to completion and returns every result in the order the names resolved, plus the final `Stats`:

```go
results, stats, err := subenum.Scan(ctx, subenum.Config{
    Domain: "example.com",            // URLs, ports and IDNs are normalized
    Rate:   100,                      // queries per second on the wire
    Types:  []string{"A", "AAAA", "CNAME"},
})
if err != nil {
    // Partial: cancelled, a wildcard zone without Force, a failed resolver
    // preflight, or the reliability guard stopped the scan. results and
    // stats still hold what was gathered.
}
for _, r := range results {
    fmt.Println(r.Name, r.Records, r.Takeover)
}
```

`Takeover` is a lead to check by hand: `dangling`, `provider:<name>` or `dangling:<name>` for a CNAME, or `dangling-ns` for a delegation to a name server that does not resolve. `Internal`{% include unreleased.html library="Internal" %} names the non-public scope (`private`, `loopback`, `link-local`, `cgnat`, `unspecified`) of an address a public name answers with, and is empty when every address is public.

Every zero value in `Config` takes the same default as the CLI, so `Config{Domain: "example.com"}` is a complete configuration that uses the bundled 5,000-word list.

## Run: a stream of events

`Run` returns a channel that streams results, notices and progress as they happen. It always ends with exactly one `KindDone` event carrying the final `Stats`, and then closes:

```go
events, err := subenum.Run(ctx, subenum.Config{Domain: "example.com"})
if err != nil {
    return err // the Config itself was invalid; no scan started
}
for ev := range events {
    switch ev.Kind {
    case subenum.KindResult:
        fmt.Println(ev.Result.Name)
    case subenum.KindNotice, subenum.KindError:
        log.Println(ev.Message)
    case subenum.KindDone:
        fmt.Printf("found %d, %d timeouts\n", ev.Stats.Found, ev.Stats.Timeout)
    }
}
```

Read the channel until it closes, or cancel `ctx`. Breaking out of the loop with a deferred `cancel()` is safe: once `ctx` is cancelled the scan stops without waiting for a reader, and its goroutines exit within about a second whether or not the channel is read. A consumer that keeps reading after cancelling still gets `KindDone` with the counts so far. While `ctx` is live, a consumer that stops reading pauses the scan once the buffer fills.

## Permutations: second-pass candidates

`Permutations`{% include unreleased.html library="Permutations" %} makes the candidates the CLI's `-permute` tries: from names a scan already found, the variants most likely to sit next to them (`api` suggests `api-dev`, `dev-api`, `dev.api`, `api2` and so on). Seeds and results are relative to the apex, like `Words`, so the output feeds a second scan directly. Pass `nil` words for the CLI's built-in list of environment, version and role names. It sends no DNS queries:

```go
seeds := []string{"api", "mail"} // api.example.com and mail.example.com were found
more, _, err := subenum.Scan(ctx, subenum.Config{
    Domain: "example.com",
    Words:  subenum.Permutations(seeds, nil),
})
```

The result is sorted and duplicate-free, and names that are not valid in DNS are left out.

## Diff: what changed since last time

`Diff`{% include unreleased.html library="Diff" %} compares two sets of results the way the CLI's `-diff` and `-diff-records` do: names added, names missing, and names whose records changed. Pass the record types both scans looked up. When a CNAME is involved only its target counts, so a re-pointed alias is a change and the rotating addresses behind a CDN are not. It sends no DNS queries:

```go
changes := subenum.Diff(lastWeek, today, []string{"A", "AAAA", "CNAME"})
for _, c := range changes.Changed {
    fmt.Println(c.Name, c.Previous, "->", c.Current)
}
```

`Removed` lists previous names the new results lack, which is not proof they are gone: they may not have been candidates this time, or their lookup failed. The CLI reports a name removed only after a fresh NXDOMAIN on a complete run, so look them up again before acting on them.

## Configuration

| Field | Default | What it does |
|---|---|---|
| `Domain` | required | Apex to enumerate under. |
| `Words` | `DefaultWords()` | Labels to try, or dotted paths such as `api.eu`. |
| `Resolver` | `8.8.8.8:53` | Trusted server: `ip:port`, `tls://host`, or `https://host/path`. |
| `ResolverPool` | none | Extra plain-UDP resolvers. Every hit is re-checked against `Resolver`. |
| `RatePerResolver`{% include unreleased.html library="RatePerResolver" %} | unlimited | Queries per second to each `ResolverPool` member. `Rate` still caps the total, so the stricter limit wins. |
| `Concurrency` | `100` | Workers looking up names at once. |
| `Timeout` | `1s` | Bound on one lookup of one record type. |
| `Attempts` | `1` | Tries per name. Only failures are retried, never NXDOMAIN. |
| `Rate` | unlimited | Queries per second on the wire, counting every type, retry and probe. |
| `Types` | `A`, `AAAA` | Record types: `A`, `AAAA`, `CNAME`, and on main also `NS`, `MX` and `TXT`. `CNAME` and `NS` populate `Result.Takeover`. |
| `Recursive`, `Depth` | off, `1` | Enumerate again under each name found. |
| `MaxQueries` | unlimited | Cap on candidate names tested. |
| `MaxDuration`{% include unreleased.html library="MaxDuration" %} | unlimited | Time budget from the start of `Run`. Then no new names are tested and the rest are counted in `Stats.Skipped`, with `Stats.Expired` set. |
| `AutoRate`{% include unreleased.html library="AutoRate" %} | false | When over a fifth of the last 200 lookups fail, halve the rate and keep going (a `NoticeRate` event says so), and raise it again once lookups succeed. It halves up to six times and not below 5 per second; only when it can slow down no further does the reliability guard apply. `Stats.RateBackoffs` and `Stats.FinalRate` report it. |
| `TakeoverProviders`{% include unreleased.html library="TakeoverProviders" %} | built-in list | Extra takeover-prone services (`{Suffix: ".example-cdn.net", Name: "example-cdn"}`) for `provider:` hints, added to the built-in list; a `Name` of `-` removes a suffix. `TakeoverProvidersOnly` uses them alone. |
| `RetryInconclusive`{% include unreleased.html library="RetryInconclusive" %} | false | Once every candidate is tried, look up each name that timed out, was refused or failed once more against `Resolver`. Names it resolves are reported but not expanded by `Recursive`. `Stats.Retried` and `Stats.Recovered` count the pass; `Stats.Inconclusive` lists the names still without an answer. |
| `Sources`{% include unreleased.html library="Sources" %} | none | Passive sources whose names are added after `Words` and looked up like them: `CertificateTransparency()`, `WaybackMachine()`, or your own `Source` (one `Names(ctx, domain)` method). A source that fails sends a `NoticeSource` event and the scan goes on. Ignored with `Simulate`. |
| `Exclude` | none | Out-of-scope names and `*.parent` branches, never queried. |
| `Force` | off | Scan a wildcard zone, dropping answers that match its fingerprint. |
| `NoAbort` | off | Keep going when more than a fifth of lookups fail. `Run` still sends the warning as a `KindError` event; `Scan` returns no error for a scan that finished. |
| `Simulate`, `HitRate`, `Seed` | off, `15`, random | Synthetic results with no DNS traffic, for tests and demos. |
| `Verbose`, `Logf` | off, stderr | Log every lookup. Lines go to `Logf`, or to standard error when it is nil. |

## Accounting

`Stats` puts each candidate name into exactly one outcome: `Found`, `NXDomain`, `Timeout`, `Refused`, `Other` or `WildcardFiltered`. Alongside are `QueriesSent`, `Skipped` (left untested by `MaxQueries` or `MaxDuration`, with `Expired` set for the latter), `Excluded`, the result counters `Takeover` and `Internal`, and the resolver-pool counters `PoolHits`, `Confirmed` and `Unconfirmed`. `Aborted` means the reliability guard stopped the scan, so the negatives mean nothing. `Wildcard` and `WildcardFingerprint` describe a wildcard zone. `RetryInconclusive` fills `Retried`, `Recovered` and `Inconclusive` (the names still without an answer), and `AutoRate` fills `RateBackoffs` and `FinalRate`. `Total()` sums the outcomes. `Verdict(interrupted)`{% include unreleased.html library="Verdict" %} applies the CLI run-quality report's rules: `VerdictComplete`, `VerdictDegraded` or `VerdictUnreliable`, with the reason in plain words (naming `Config` fields such as `MaxQueries`).

## Testing your integration

Set `Simulate` in tests and examples. It exercises the full pipeline with no DNS queries, and a fixed `Seed` makes the results reproducible:

```go
results, _, err := subenum.Scan(ctx, subenum.Config{
    Domain:   "example.com",
    Words:    []string{"www", "api", "mail", "dev"},
    Simulate: true,
    HitRate:  50,
    Seed:     42,
})
```

> **Authorized use only.** Only enumerate domains you own or have permission to test.
