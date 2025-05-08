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

```bash
./subenum -w wordlist.txt -progress=false example.com | grep "Found:" > subdomains.txt
```

## Integration with Other Tools

`subenum` can be easily integrated with other security tools:

### Example: Piping to Subdomain Takeover Scanner

```bash
./subenum -w wordlist.txt -progress=false example.com | grep "Found:" | cut -d ' ' -f 2 | your-takeover-tool
```

### Example: Use with Multiple Domains

Using the provided `multi_domain_scan.sh` script:

```bash
cd examples
./multi_domain_scan.sh sample_domains.txt
```

## Continuous Integration / Automated Testing

For CI/CD environments, you can use the version flag to ensure the correct version is installed:

```bash
./subenum -version
# Output: subenum v0.2.0
``` 