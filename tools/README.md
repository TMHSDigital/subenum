# Wordlist Generator for subenum

This directory contains utility tools to help with subdomain enumeration tasks.

## wordlist-gen.go

A simple utility for generating custom wordlists for subdomain enumeration.

### Features

- Includes common subdomain prefixes 
- Extracts meaningful terms from domain names
- Creates combinations with custom prefixes
- Ensures no duplicate entries (case-insensitive)
- Deterministic: the same flags always produce a byte-identical file
- Strips the public suffix, including second-level ones such as `.co.uk`
- Writes only valid DNS labels, and exits non-zero when nothing would be written

### Usage

```bash
# Build the tool
go build -buildvcs=false -o wordlist-gen wordlist-gen.go

# Generate a basic wordlist with common prefixes
./wordlist-gen -o my-wordlist.txt

# Generate a domain-specific wordlist
./wordlist-gen -domain company-name.com -o company-wordlist.txt

# Add custom combinations
./wordlist-gen -domain company-name.com -combine "dev,test,staging" -f -o company-wordlist.txt

# Learn an organisation's naming habits from earlier results
./wordlist-gen -from results.jsonl -from old-scan.txt -min-count 2 -o learned.txt
```

`-from` reads earlier subenum results in any output format (text, JSON, JSONL or CSV, the formats `-diff` reads), takes the labels of each name below its apex (`api.k8s.example.com` gives `api` and `k8s`), and writes them first, most frequent first, ahead of the common prefixes, which are not repeated. The apex is `-domain` when a name ends in it, and otherwise the registrable domain (`example.com`, `acme.co.uk`).

### Parameters

| Flag | Description | Default |
|------|-------------|---------|
| `-o` | Output file path; an existing file is never overwritten without `-f` | `wordlist.txt` |
| `-f` | Overwrite the output file if it exists | `false` |
| `-common` | Include common subdomain prefixes | `true` |
| `-domain` | Domain to extract terms from | `""` (empty) |
| `-combine` | Comma-separated prefixes to combine with other terms; each must be a valid DNS label | `""` (empty) |
| `-from` | Earlier subenum results file to learn labels from, most frequent first; repeatable | none |
| `-min-count` | With `-from`, drop labels seen fewer than this many times | `1` |
| `-v` | Print every generated entry to stdout | `false` |

### Example

```bash
./wordlist-gen -domain acme-corp.com -combine "dev,test,prod,api" -o acme-wordlist.txt
```

This will:
1. Extract "acme" and "corp" from the domain
2. Add common subdomain prefixes
3. Add "dev", "test", "prod", and "api"
4. Create combinations like "dev-mail", "test-api", etc.
5. Save all unique entries to `acme-wordlist.txt`

### Integration with subenum

Use generated wordlists with subenum for more targeted scanning:

```bash
# Generate a custom wordlist
cd tools
go build -buildvcs=false -o wordlist-gen wordlist-gen.go
./wordlist-gen -domain target.com -o ../target-wordlist.txt

# Use with subenum
cd ..
./subenum -w target-wordlist.txt -v target.com
```

## Legal Note

As with all components of this project, this tool is provided for **educational and legitimate security testing purposes only**. Only use generated wordlists for domains you have explicit permission to test. 