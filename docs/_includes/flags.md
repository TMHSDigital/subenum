<!-- Generated from subenum's flags by `make docs-flags`; do not edit. -->

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-attempts <int>` | - | Total DNS resolution attempts per subdomain, 1 = no retry (default 1) |
| `-ct` | - | Add names from Certificate Transparency logs (crt.sh, one HTTPS request per target, no API key) as candidates and -permute seeds |
| `-dL <string>` | - | File of apex domains to scan, one per line (- for stdin); replaces the &lt;domain&gt; argument |
| `-depth <int>` | 1 | Max recursion depth when -recursive is set (1 = no recursion) |
| `-diff <string>` | - | Previous results file (any -format); report only names added or removed since then, and exit 4 when there are changes |
| `-dns-server <string>` | 8.8.8.8:53 | DNS server: ip:port (UDP, TCP fallback), tls://host[:853] (DNS over TLS) or https://host/path (DNS over HTTPS) |
| `-exclude <string>` | - | Comma-separated out-of-scope names and \*.parent patterns; never queried or expanded |
| `-exclude-file <string>` | - | File of out-of-scope names and \*.parent patterns, one per line (# comments allowed) |
| `-force` | - | Continue scanning even if wildcard DNS is detected |
| `-format <string>` | text | Output format: text, json, jsonl, or csv |
| `-hit-rate <int>` | 15 | In simulation mode, percentage of names that resolve (1-100) |
| `-max-queries <int>` | - | Max candidate names to test (0 = unlimited); each name sends one query per record type, per attempt |
| `-no-abort` | - | Do not abort when the resolver failure rate exceeds 20% (warning is still emitted) |
| `-o <string>` | - | Write results to file (in addition to stdout) |
| `-permute` | - | After each scan, scan permutations of the names found (api -&gt; api-dev, dev-api, dev.api, api2, ...) |
| `-print-config` | - | Print every setting's effective value and its source (flag, env, config or default), then exit |
| `-progress` | true | Show progress during scanning |
| `-r <string>` | - | File of resolvers (ip or ip:port, one per line) to spread queries over; every hit is re-validated against -dns-server |
| `-rate <int>` | - | Max DNS queries per second on the wire, all workers combined; counts every record type, retry and wildcard probe (0 = unlimited) |
| `-recursive` | - | Recursively enumerate subdomains of discovered subdomains |
| `-resume <string>` | - | Resume an interrupted run from its state file (no other arguments) |
| `-retries <int>` | - | Deprecated: use -attempts instead |
| `-sarif <string>` | - | Write takeover candidates to this file as SARIF 2.1.0, for GitHub code scanning (needs CNAME in -type) |
| `-seed <uint>` | - | In simulation mode, seed for reproducible results (0 = random; the seed used is printed) |
| `-seeds <string>` | - | Results file (any -format) whose names also seed -permute; implies -permute |
| `-show-records` | - | In text format, append each result's records (TYPE=value) |
| `-silent` | - | Pipeline mode: bare result names on stdout, and only errors (and a simulation warning) on stderr |
| `-simulate` | - | Run in simulation mode without actual DNS queries (for testing) |
| `-simulate-zone <string>` | - | Lab mode: answer every query from this scenario file via a local DNS server, so no traffic leaves the machine (see the Labs page) |
| `-state <string>` | subenum-resume.json | Where an interrupted run saves its state for -resume |
| `-stats <string>` | - | Write a JSON run-quality report (outcomes, queries sent, verdict) to this file |
| `-t <int>` | 100 | Number of concurrent workers |
| `-timeout <int>` | 1000 | DNS lookup timeout in milliseconds |
| `-tui` | - | Launch the interactive terminal UI (all other flags are ignored) |
| `-type <string>` | A,AAAA | Comma-separated DNS record types to look up: A, AAAA, CNAME |
| `-v` | - | Enable verbose output |
| `-version` | - | Show version information |
| `-w <string>` | - | Path to the wordlist file (- for stdin); omitted: the bundled top-5000 list |
