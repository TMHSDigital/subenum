# Advanced Usage Examples for `subenum`

## Using Custom DNS Servers

Using alternative DNS servers can help in several scenarios:
- When your default DNS provider is slow or unreliable
- To avoid rate limiting from your ISP
- To potentially get different results based on how different DNS providers cache records

### Example: Using Cloudflare's DNS

```bash
./subenum -w wordlist.txt -dns-server 1.1.1.1:53 example.com
```

### Example: Using Google's DNS (explicit)

```bash
./subenum -w wordlist.txt -dns-server 8.8.8.8:53 example.com
```

## Verbose Mode

Verbose mode is useful for:
- Debugging connection issues
- Understanding which domains failed to resolve and why
- Getting more detailed information about successful resolutions, including IP addresses

### Example: Basic Verbose Mode

```bash
./subenum -w wordlist.txt -v example.com
```

### Example: Verbose Mode with Custom Settings

```bash
./subenum -w wordlist.txt -v -t 50 -timeout 2000 -dns-server 1.1.1.1:53 example.com
```

## Progress Reporting

Progress reporting is enabled by default but can be controlled:

### Example: Disable Progress Reporting

This is useful in scripted environments or when piping output to another tool:

```bash
./subenum -w wordlist.txt -progress=false example.com
```

## Combining Multiple Features

You can combine multiple options for your specific needs:

### Example: High Performance Scan

```bash
./subenum -w large_wordlist.txt -t 200 -timeout 500 example.com
```

### Example: Thorough Scan with Verbose Output

```bash
./subenum -w comprehensive_wordlist.txt -v -t 50 -timeout 3000 -dns-server 1.1.1.1:53 example.com
```

## Output Redirection

You can save the results to a file using standard shell redirection:

### Example: Save All Output (Including Verbose)

```bash
./subenum -w wordlist.txt -v example.com > all_output.txt 2>&1
```

### Example: Save Only Found Subdomains

Results go to stdout and progress to stderr, so you can pipe stdout directly:

```bash
./subenum -w wordlist.txt example.com > subdomains.txt
```

## Integration with Other Tools

`subenum` can be easily integrated with other security tools:

### Example: Piping to Subdomain Takeover Scanner

```bash
./subenum -w wordlist.txt example.com | your-takeover-tool
```

### Example: Use with Multiple Domains

Using the provided `multi_domain_scan.sh` script:

```bash
cd examples
./multi_domain_scan.sh sample_domains.txt
```

## Saving Results to a File

Use `-o` to write discovered subdomains to a file while still printing them to stdout:

```bash
./subenum -w wordlist.txt -o results.txt example.com
```

Combine with other flags for a full scan that saves output:

```bash
./subenum -w wordlist.txt -v -t 150 -o scan_results.txt example.com
```

## Multiple Attempts for Unreliable Networks

Use `-attempts` to set the total number of DNS resolution attempts per subdomain. Useful on flaky connections or rate-limited resolvers:

```bash
./subenum -w wordlist.txt -attempts 3 example.com
```

Combine with a longer timeout for maximum resilience:

```bash
./subenum -w wordlist.txt -attempts 3 -timeout 2000 -dns-server 1.1.1.1:53 example.com
```

## Simulation Mode

Use `-simulate` to run without making any real DNS queries. Ideal for demonstrations, CI testing, or exploring the tool's output format:

```bash
./subenum -simulate -w examples/sample_wordlist.txt example.com
```

Adjust the simulated hit rate (percentage of subdomains that appear to resolve):

```bash
./subenum -simulate -hit-rate 30 -w examples/sample_wordlist.txt example.com
```

Simulation mode with verbose output shows fake IPs and timings:

```bash
./subenum -simulate -hit-rate 25 -v -w examples/sample_wordlist.txt example.com
```

## Rate Limiting

Use `-rate` to cap the total number of DNS queries per second across the whole worker pool. This is useful against rate-limited resolvers or to stay under a target query budget. `0` (the default) means unlimited:

```bash
./subenum -w wordlist.txt -rate 50 example.com
```

The limiter is context-aware, so `Ctrl+C` stays responsive while workers are waiting on it.

## Output Formats

By default `subenum` prints human-readable `Found:` lines. Use `-format` to emit structured output instead. The `-o` file honors the same format.

### JSON

Emits a single JSON array of objects, each with the subdomain and its resolved records:

```bash
./subenum -w wordlist.txt -format json example.com
```

```json
[
  {
    "subdomain": "www.example.com",
    "records": [{ "type": "A", "value": "93.184.216.34" }]
  }
]
```

JSON is buffered and written once at completion (it is a single document, so it does not stream like text and CSV).

### CSV

Streams a header followed by one `subdomain,type,value` row per record:

```bash
./subenum -w wordlist.txt -format csv -o results.csv example.com
```

```csv
subdomain,type,value
www.example.com,A,93.184.216.34
```

## Continuous Integration / Automated Testing

For CI/CD environments, you can use the version flag to ensure the correct version is installed:

```bash
./subenum -version
# Output: subenum v0.6.0
```

Use simulation mode in CI pipelines to test the tool's behaviour without network access:

```bash
./subenum -simulate -hit-rate 20 -w examples/sample_wordlist.txt -o /tmp/results.txt example.com
``` 