<!-- Generated from subenum's flags by `make docs-flags`; do not edit. -->

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-attempts <int>` | 1 | Total DNS resolution attempts per subdomain, 1 = no retry (default 1) |
| `-auto-rate` | - | When over 20% of the last 200 lookups fail, halve the query rate and keep going (up to 6 times, down to 5 queries/s) instead of aborting; speed back up once lookups succeed |
| `-axfr` | - | Try a zone transfer (AXFR) from each of the target's name servers first, and add the names it gives as candidates and -permute seeds; also report a zone that DNSSEC NSEC lets anyone walk |
| `-ct` | - | Add names from Certificate Transparency logs (crt.sh, one HTTPS request per target, no API key) as candidates and -permute seeds |
| `-dL <string>` | - | File of apex domains to scan, one per line (- for stdin); replaces the &lt;domain&gt; argument |
| `-depth <int>` | 1 | Max recursion depth when -recursive is set (1 = no recursion) |
| `-diff <string>` | - | Previous results file (any -format); report only names added or removed since then, and exit 4 when there are changes |
| `-diff-records` | - | With -diff, also report names whose records changed (a re-pointed CNAME, moved addresses), compared over the -type record types; needs a json, jsonl or csv -diff file |
| `-dns-server <string>` | 8.8.8.8:53 | DNS server: ip[:port] (UDP, TCP fallback), tls://host[:853] (DNS over TLS) or https://host/path (DNS over HTTPS) |
| `-dry-run` | - | Print the plan without scanning: candidates after dedupe and -exclude, query and duration estimates, and the resolver preflight (its only DNS query, also sent to each -r pool resolver); then exit |
| `-exclude <string>` | - | Comma-separated out-of-scope names and \*.parent patterns; never queried or expanded |
| `-exclude-file <string>` | - | File of out-of-scope names and \*.parent patterns, one per line (# comments allowed) |
| `-follow-records` {% include unreleased.html flag="follow-records" %} | - | Also test the names under the target that found names' CNAME, MX and NS records point at, once each, unless they are already candidates; they count against -max-queries |
| `-force` | - | Continue scanning even if wildcard DNS is detected |
| `-format <string>` | text | Output format: text, json, jsonl, or csv |
| `-hit-rate <int>` | 15 | In simulation mode, percentage of names that resolve (1-100) |
| `-hosts <file>` {% include unreleased.html flag="hosts" %} | - | A file of full host names to resolve instead of a wordlist, one per line (- for stdin); each target looks up only the names under it, names under no target are skipped |
| `-inconclusive <string>` | - | Write the names still without an answer (timeout, refused, other) to this file, one per line, to rescan with -w |
| `-log-format <string>` | text | Diagnostics format on stderr: text, or json for one JSON object per line (level, kind, target, message); results on stdout are unchanged |
| `-max-duration <duration>` | 0s | Time budget for the whole run, e.g. 20m (0 = unlimited); then no new names are tested, lookups in flight finish, and the run ends with its report, a degraded verdict and saved state for -resume to continue from |
| `-max-queries <int>` | - | Max candidate names to test (0 = unlimited); each name sends one query per record type, per attempt |
| `-no-abort` | - | Do not abort when the resolver failure rate exceeds 20% (warning is still emitted) |
| `-nsec-walk` {% include unreleased.html flag="nsec-walk" %} | - | When the target's zone is signed with plain DNSSEC NSEC, list it by walking the NSEC chain at its name server first, and add the names as candidates and -permute seeds; one query per name, paced by -rate and bounded by -max-queries, -max-duration and -exclude |
| `-o <file>` | - | Write results to file (in addition to stdout); repeat for several files, each in -format or in the format named as a prefix, format:path (jsonl:results.jsonl) |
| `-permute` | - | After each scan, scan permutations of the names found (api -&gt; api-dev, dev-api, dev.api, api2, ...) |
| `-print-config` | - | Print every setting's effective value and its source (flag, env, config or default), then exit |
| `-progress` | true | Show progress during scanning |
| `-r <string>` | - | File of resolvers (ip[:port], tls://host[:port] or https://host/path, one per line) to spread queries over; every hit is re-validated against -dns-server |
| `-rate <int>` | - | Max DNS queries per second on the wire, all workers combined; counts every record type, retry and wildcard probe (0 = unlimited) |
| `-rate-per-resolver <int>` | - | With -r, max DNS queries per second sent to each pool resolver; -rate still caps the total (0 = unlimited) |
| `-recursive` | - | Recursively enumerate subdomains of discovered subdomains |
| `-recursive-w <file>` {% include unreleased.html flag="recursive-w" %} | - | Path to a wordlist file (- for stdin) of the labels -recursive tries under each name it finds, at depth 2 and below; repeat to combine several; omitted: the -w list |
| `-resume <string>` | - | Resume a run that was interrupted, ran out of -max-duration or was aborted, from its state file (no other arguments but the pacing flags -rate, -rate-per-resolver, -t, -timeout, -attempts, -auto-rate, -no-abort and -max-duration) |
| `-retries <int>` | - | Deprecated: use -attempts instead |
| `-retry-inconclusive` | - | After each scan, look up once more (against -dns-server) every name that timed out, was refused or failed; names it resolves are reported, but not expanded by -recursive |
| `-sarif <string>` | - | Write takeover candidates to this file as SARIF 2.1.0, for GitHub code scanning (needs CNAME or NS in -type) |
| `-seed <uint>` | - | In simulation mode, seed for reproducible results (0 = random; the seed used is printed) |
| `-seeds <string>` | - | Results file (any -format) whose names also seed -permute; implies -permute |
| `-show-records` | - | In text format, append each result's records (TYPE=value) |
| `-silent` | - | Pipeline mode: bare result names on stdout, and only errors (and a simulation warning) on stderr |
| `-simulate` | - | Run in simulation mode without actual DNS queries (for testing) |
| `-simulate-zone <string>` | - | Lab mode: answer every query from this scenario file, or a built-in scenario such as lab1 (lab1-lab6, lab7, lab8, lab9), via a local DNS server, so no traffic leaves the machine (see the Labs page) lab7, lab8, lab9: {% include unreleased.html value="simulate-zone=lab7" %} |
| `-sources <string>` | - | Comma-separated keyless passive sources whose names become candidates and -permute seeds: ct (Certificate Transparency, crt.sh), wayback (Wayback Machine); one HTTPS request per source and target |
| `-srv` {% include unreleased.html flag="srv" %} | - | Also look up a built-in list of about 50 service names (\_sip.\_tcp, \_autodiscover.\_tcp, \_ldap.\_tcp, ...) under each target; needs SRV in -type |
| `-state <string>` | subenum-resume.json | Where a run that was interrupted, ran out of -max-duration or was aborted saves its state for -resume |
| `-stats <string>` | - | Write a JSON run-quality report (outcomes, queries sent, verdict) to this file |
| `-t <int>` | 100 | Number of concurrent workers |
| `-takeover-providers <string>` | - | File of takeover-prone services, one "&lt;suffix&gt; &lt;name&gt;" per line (.example-cdn.net example-cdn; # comments allowed; name - removes a suffix), added to the built-in list for takeover hints |
| `-takeover-providers-only` | - | Use only the -takeover-providers file, not the built-in provider list |
| `-timeout <int>` | 1000 | DNS lookup timeout in milliseconds |
| `-tui` | - | Launch the interactive terminal UI, its form pre-filled from the other flags and the domain argument |
| `-type <string>` | A,AAAA | Comma-separated DNS record types to look up: A, AAAA, CNAME, NS, MX, TXT, SRV (CNAME and NS also check for takeovers; with NS, a name that fails with SERVFAIL is asked of the zone's own name servers for its delegation) SRV: {% include unreleased.html value="type=SRV" %} |
| `-v` | - | Enable verbose output |
| `-version` | - | Show version information |
| `-w <file>` | - | Path to a wordlist file (- for stdin); repeat to combine several, deduplicated; omitted: the bundled top-5000 list |
