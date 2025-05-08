# subenum

[![Go Report Card](https://goreportcard.com/badge/github.com/yourusername/subenum)](https://goreportcard.com/report/github.com/yourusername/subenum)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/yourusername/subenum/go.yml?branch=main)](https://github.com/yourusername/subenum/actions)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/yourusername/subenum)](https://github.com/yourusername/subenum/releases)
[![License](https://img.shields.io/github/license/yourusername/subenum)](https://github.com/yourusername/subenum/blob/main/LICENSE)
[![Docker](https://img.shields.io/badge/docker-supported-blue)](https://github.com/yourusername/subenum/blob/main/docs/docker.md)

A Go-based CLI tool for subdomain enumeration.

## Description

`subenum` takes a domain and a wordlist as input. It then attempts to resolve `word.domain` for each word in the wordlist using DNS lookups. Valid subdomains that return an A or CNAME record are printed to the console.

## Cybersecurity Context & Importance

Subdomain enumeration is a crucial first step in the reconnaissance phase of a penetration test or security assessment. Its primary goal is to map out the target organization's digital footprint. Here's why it's important:

*   **Expanding Attack Surface Discovery**: Organizations often have numerous subdomains for different services, applications (e.g., `blog.example.com`, `api.example.com`), or development/staging environments (e.g., `dev.example.com`, `staging.app.example.com`). Many of these might not be publicly linked or widely known. Each discovered subdomain is a potential entry point for an attacker.
*   **Identifying Forgotten or Unmaintained Assets**: Companies might have old subdomains pointing to outdated, unpatched applications or servers. These "forgotten" assets can be highly vulnerable and are prime targets.
*   **Finding Hidden or Test Environments**: Subdomains like `test.example.com` or `uat.example.com` may have weaker security configurations, use default credentials, or expose sensitive debugging information that could be leveraged.
*   **Discovering Different Technologies/Services**: Different subdomains can host applications built with various technologies. Knowing this allows security professionals to tailor vulnerability scanning and exploitation techniques to specific technology stacks.
*   **Bypassing Security Controls**: Security measures like Web Application Firewalls (WAFs) might be rigorously applied to the main domain but not consistently across all subdomains. A vulnerable service on an "unprotected" subdomain could offer a path into the internal network.
*   **Targeting Specific Services**: Subdomains often give clues about the services they host (e.g., `mail.example.com`, `vpn.example.com`, `ftp.example.com`). This allows for focused attacks against known vulnerabilities in those types of services.
*   **Information Gathering for Further Attacks**: The structure and naming conventions of subdomains can provide insights into the organization's internal structure, naming schemes, or technologies in use, which can be valuable for social engineering or other targeted attacks.

By discovering more subdomains, security testers can identify a broader range of potential vulnerabilities and provide a more comprehensive assessment of an organization's security posture.

## Legal & Ethical Usage Disclaimer

**IMPORTANT**: This tool is provided for **educational and legitimate security testing purposes only**. 

*   **Authorization Required**: Only use this tool on systems and domains for which you have explicit permission to test.
*   **Prohibited Uses**: This software must NOT be used for:
    *   Unauthorized access to systems or networks
    *   Data theft or exfiltration
    *   Disruption of services (DoS/DDoS)
    *   Any activity prohibited by applicable local, national, or international laws
*   **Responsible Use**: Always follow responsible disclosure practices if you discover vulnerabilities.
*   **Legal Compliance**: Users are solely responsible for ensuring their use of this tool complies with all relevant laws, regulations, and organizational policies.

The developers and contributors of `subenum` explicitly prohibit any use of this software for malicious purposes or to cause harm. Violation of these terms may subject you to legal action.

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/subenum.git
cd subenum

# Build the tool
go build -buildvcs=false
```

### Using Docker

You can also run `subenum` using Docker:

```bash
# Build the Docker image
docker build -t subenum .

# Run with Docker
docker run --rm -v $(pwd)/data:/data subenum -w /data/wordlist.txt example.com
```

### Using Make

The project includes a Makefile for common tasks:

```bash
# Show available commands
make help

# Build the binary
make build

# Run with default settings
make run
```

## Usage

```bash
go build
./subenum -w <wordlist_file> <domain>
```

### Flags:

-   `-w <file>`: Path to the wordlist file (required).
-   `-t <number>`: Number of concurrent workers (default: 100).
-   `-timeout <ms>`: DNS lookup timeout in milliseconds (default: 1000ms).
-   `-dns-server <ip:port>`: DNS server to use for lookups (default: 8.8.8.8:53).
-   `-v`: Enable verbose output with detailed information about each lookup.
-   `-progress`: Show scan progress (default: true, use `-progress=false` to disable).
-   `-version`: Show version information and exit.

### Output:

Without verbose mode, the tool only outputs successfully resolved subdomains:
```
Found: blog.example.com
Found: mail.example.com
```

With verbose mode (`-v`), you'll see additional information:
```
Starting subenum v0.2.0
Target domain: example.com
Wordlist: wordlist.txt
Concurrency: 100 workers
Timeout: 1000 ms
DNS Server: 8.8.8.8:53
---
Total wordlist entries: 50
Resolved: www.example.com (IP: 93.184.216.34) in 52.789ms
Found: www.example.com
Failed to resolve: nonexistent.example.com (Error: lookup nonexistent.example.com: no such host) in 81.234ms
Progress: 100.0% (50/50) | Found: 3

Scan completed for example.com
Processed 50 subdomain prefixes
Found 3 valid subdomains
```

## Example

Assuming you have a wordlist file named `words.txt` with the following content:

```
blog
mail
www
shop
```

And you want to enumerate subdomains for `example.com`:

```bash
./subenum -w words.txt example.com
```

Potential output:

```
Found: blog.example.com
Found: mail.example.com
Found: www.example.com
```

### Examples with Additional Options

Using a custom DNS server:
```bash
./subenum -w words.txt -dns-server 1.1.1.1:53 example.com
```

Enabling verbose output while using higher concurrency and longer timeout:
```bash
./subenum -w words.txt -v -t 200 -timeout 2000 example.com
```

Disabling progress reporting (useful for scripting):
```bash
./subenum -w words.txt -progress=false example.com
```

### Simulation Mode for Safe Testing

The tool includes a simulation mode for safely testing functionality without performing actual DNS queries:

```bash
# Safe simulation mode (no actual DNS queries)
./subenum -simulate -w examples/sample_wordlist.txt example.com
```

In simulation mode:
- **No actual DNS queries** are performed (completely network-safe)
- Results are randomly generated based on common patterns
- All output is clearly marked as simulated
- You can adjust the "hit rate" (percentage of domains that resolve):
  ```bash
  # Simulate with 25% of domains resolving
  ./subenum -simulate -hit-rate 25 -w examples/sample_wordlist.txt example.com
  ```

This mode is perfect for:
- Educational demonstrations
- Testing the tool functionality
- Understanding the output format
- Developing additional features

## Contributing

See [CONTRIBUTING.md](docs/CONTRIBUTING.md) for details on how to contribute to this project.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
