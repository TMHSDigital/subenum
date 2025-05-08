# Wordlist Generator for subenum

This directory contains utility tools to help with subdomain enumeration tasks.

## wordlist-gen.go

A simple utility for generating custom wordlists for subdomain enumeration.

### Features

- Includes common subdomain prefixes 
- Extracts meaningful terms from domain names
- Creates combinations with custom prefixes
- Ensures no duplicate entries
- Smart formatting for better enumeration results

### Usage

```bash
# Build the tool
go build -o wordlist-gen wordlist-gen.go

# Generate a basic wordlist with common prefixes
./wordlist-gen -o my-wordlist.txt

# Generate a domain-specific wordlist
./wordlist-gen -domain company-name.com -o company-wordlist.txt

# Add custom combinations
./wordlist-gen -domain company-name.com -combine "dev,test,staging" -o company-wordlist.txt
```

### Parameters

| Flag | Description | Default |
|------|-------------|---------|
| `-o` | Output file path | `wordlist.txt` |
| `-common` | Include common subdomain prefixes | `true` |
| `-domain` | Domain to extract terms from | `""` (empty) |
| `-combine` | Comma-separated prefixes to combine with other terms | `""` (empty) |

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
go build -o wordlist-gen wordlist-gen.go
./wordlist-gen -domain target.com -o ../target-wordlist.txt

# Use with subenum
cd ..
./subenum -w target-wordlist.txt -v target.com
```

## Legal Note

As with all components of this project, this tool is provided for **educational and legitimate security testing purposes only**. Only use generated wordlists for domains you have explicit permission to test. 