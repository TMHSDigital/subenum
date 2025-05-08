---
layout: default
title: Home
---

# subenum

A Go-based CLI tool for subdomain enumeration designed for educational purposes and legitimate security testing.

## Features

- Fast, concurrent DNS lookup of subdomains using customizable wordlists
- Configurable concurrency level and timeout settings
- Support for custom DNS servers
- Verbose mode for detailed output
- Real-time progress tracking
- Docker support for containerized usage
- Extensive documentation and examples

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/subenum.git
cd subenum

# Build the tool
go build
```

### Using Docker

```bash
# Clone the repository
git clone https://github.com/yourusername/subenum.git
cd subenum

# Build the Docker image
docker build -t subenum .

# Run with Docker
docker run --rm -v $(pwd)/data:/data subenum -w /data/wordlist.txt example.com
```

## Quick Start

```bash
# Basic usage
./subenum -w wordlist.txt example.com

# With custom settings
./subenum -w wordlist.txt -t 200 -timeout 1500 -dns-server 1.1.1.1:53 -v example.com
```

### Using Make

The project includes a Makefile for common tasks:

```bash
# Show available commands
make help

# Build and run with default settings
make run

# Build and run with verbose output
make run-verbose

# Run with Docker
make docker-build docker-run
```

## Documentation

- [Usage Guide](https://github.com/yourusername/subenum#usage)
- [Advanced Usage Examples](https://github.com/yourusername/subenum/blob/main/examples/advanced_usage.md)
- [Docker Usage](#using-docker)
- [Architecture](ARCHITECTURE.html)
- [Developer Guide](DEVELOPER_GUIDE.html)
- [Contributing](CONTRIBUTING.html)

## Ethical Use

This tool is provided for **educational and legitimate security testing purposes only**. Users must ensure they have proper authorization before conducting subdomain enumeration on any domains. See the [LICENSE](https://github.com/yourusername/subenum/blob/main/LICENSE) file for detailed terms of use.

## License

This project is licensed under the MIT License with additional restrictions against malicious use. 