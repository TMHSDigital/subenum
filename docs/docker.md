---
layout: default
title: Docker Usage
---

# Docker Usage Guide for subenum

This guide explains how to use `subenum` with Docker for a containerized subdomain enumeration setup.

## Prerequisites

- Docker installed on your system
- Docker Compose (optional, for easy management)

## Building the Docker Image

### Using docker build

```bash
# Clone the repository (if you haven't already)
git clone https://github.com/yourusername/subenum.git
cd subenum

# Build the Docker image
docker build -t subenum .
```

### Using make

If you have Make installed, you can use the provided Makefile:

```bash
make docker-build
```

## Running subenum with Docker

### Basic Usage

```bash
# Run subenum with a wordlist in the data directory
docker run --rm -v $(pwd)/data:/data subenum -w /data/wordlist.txt example.com
```

### Using Docker Compose

The project includes a `docker-compose.yml` file for easier management:

```bash
# Start container with the default configuration
docker-compose up

# Run with custom parameters
docker-compose run --rm subenum -w /data/custom-wordlist.txt -v -t 200 yourdomain.com
```

## Volume Mounting

The Docker container is configured with a volume mount point at `/data`. This allows you to:

1. Use your own wordlists
2. Save output from the container to your host system

Example of mounting a custom directory:

```bash
docker run --rm -v /path/to/your/files:/data subenum -w /data/your-wordlist.txt -v target.com
```

## Docker Environment Structure

- `/root/subenum`: The main executable
- `/root/examples/`: Contains example files and wordlists from the repository
- `/data/`: Mount point for your custom files

## Troubleshooting

### DNS Resolution Issues

If you're experiencing DNS resolution problems in the container:

```bash
# Try using a different DNS server
docker run --rm -v $(pwd)/data:/data subenum -w /data/wordlist.txt -dns-server 1.1.1.1:53 example.com
```

### File Permission Problems

If you encounter permission issues with mounted volumes:

```bash
# Run the container with your user ID
docker run --rm -v $(pwd)/data:/data --user $(id -u):$(id -g) subenum -w /data/wordlist.txt example.com
```

## Security Notes

Remember that `subenum` is provided for educational and legitimate security testing purposes only. All the ethical guidelines and legal restrictions from the main project apply equally when using the Docker version.

Always ensure you have explicit permission to scan any domain. 