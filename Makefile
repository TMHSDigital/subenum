.PHONY: all build test test-short bench clean lint tidy tui run run-verbose run-custom require-domain \
	simulate simulate-verbose simulate-custom wordlist wordlist-gen docker-build docker-run docker-simulate help

# Default Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOVET=$(GOCMD) vet
BINARY_NAME=subenum
WORDLIST_GEN=wordlist-gen
VERSION ?= $(shell git describe --tags --dirty --always 2>/dev/null || echo dev)
LDFLAGS = -ldflags "-X main.Version=$(VERSION)"

# Default run parameters. Live targets (run, run-verbose, run-custom,
# docker-run) have no default DOMAIN: they send real DNS queries, so you must
# name a domain you own or are authorized to test, e.g. make run DOMAIN=...
WORDLIST=examples/sample_wordlist.txt
CONCURRENCY=100
TIMEOUT=1000
DNS_SERVER=8.8.8.8:53

# Simulation parameters. Simulated targets send no DNS traffic, so they fall
# back to example.com when DOMAIN is not set.
HIT_RATE=15
SIM_DOMAIN=$(or $(DOMAIN),example.com)

# Wordlist generator parameters
WL_DOMAIN ?= $(SIM_DOMAIN)
WL_COMBINE=dev,staging,test,api
WL_OUTPUT=custom-wordlist.txt

all: build

build:
	$(GOBUILD) -buildvcs=false $(LDFLAGS) -o $(BINARY_NAME)

test:
	$(GOTEST) -v ./...

test-short:
	$(GOTEST) -v ./... -short

# Dispatcher throughput on a 1M-entry simulated scan; overhead must stay
# linear in wordlist size (#49).
bench:
	$(GOTEST) ./internal/scan -run '^$$' -bench BenchmarkRun1M -benchtime 1x

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME).exe
	rm -f tools/$(WORDLIST_GEN)

lint:
	golangci-lint run

# go mod tidy. The go directive must stay go 1.24.2 (bubbles requires it).
tidy:
	go mod tidy

# Build wordlist generator
wordlist-gen:
	$(GOBUILD) -buildvcs=false -o tools/$(WORDLIST_GEN) tools/wordlist-gen.go

# Generate a custom wordlist
wordlist: wordlist-gen
	tools/$(WORDLIST_GEN) -domain $(WL_DOMAIN) -combine $(WL_COMBINE) -o $(WL_OUTPUT)
	@echo "Generated wordlist: $(WL_OUTPUT)"
	@echo "Use it with: make WORDLIST=$(WL_OUTPUT) DOMAIN=$(WL_DOMAIN) run-verbose"

# Launch the interactive TUI (one-click, no arguments needed)
tui: build
	./$(BINARY_NAME) -tui

# Live targets refuse to run without an explicit DOMAIN.
require-domain:
ifndef DOMAIN
	$(error Live scans send real DNS queries. Set DOMAIN to a domain you own or are authorized to test, e.g. make run DOMAIN=yourdomain.com, or use make simulate)
endif

# Run with default parameters (LIVE)
run: require-domain build
	./$(BINARY_NAME) -w $(WORDLIST) -t $(CONCURRENCY) -timeout $(TIMEOUT) -dns-server $(DNS_SERVER) $(DOMAIN)

# Run with verbose output (LIVE)
run-verbose: require-domain build
	./$(BINARY_NAME) -w $(WORDLIST) -t $(CONCURRENCY) -timeout $(TIMEOUT) -dns-server $(DNS_SERVER) -v $(DOMAIN)

# Run in simulation mode (safe, no actual DNS queries)
simulate: build
	./$(BINARY_NAME) -simulate -hit-rate $(HIT_RATE) -w $(WORDLIST) -t $(CONCURRENCY) -timeout $(TIMEOUT) $(SIM_DOMAIN)

# Run in simulation mode with verbose output (safe, no actual DNS queries)
simulate-verbose: build
	./$(BINARY_NAME) -simulate -hit-rate $(HIT_RATE) -w $(WORDLIST) -t $(CONCURRENCY) -timeout $(TIMEOUT) -v $(SIM_DOMAIN)

# Generate a wordlist and use it with simulation mode
simulate-custom: wordlist build
	./$(BINARY_NAME) -simulate -hit-rate $(HIT_RATE) -w $(WL_OUTPUT) -t $(CONCURRENCY) -timeout $(TIMEOUT) -v $(WL_DOMAIN)

# Generate a wordlist and immediately use it (LIVE)
run-custom: require-domain wordlist build
	./$(BINARY_NAME) -w $(WL_OUTPUT) -t $(CONCURRENCY) -timeout $(TIMEOUT) -dns-server $(DNS_SERVER) -v $(DOMAIN)

# Docker commands
docker-build:
	docker build --build-arg VERSION=$(VERSION) -t $(BINARY_NAME) .

# LIVE. $(CURDIR) rather than $(PWD), which is empty under Windows make.
docker-run: require-domain
	docker run --rm -v "$(CURDIR)/data:/data" $(BINARY_NAME) -w /data/wordlist.txt -v $(DOMAIN)

# Run Docker in simulation mode (completely safe)
docker-simulate:
	docker build --build-arg VERSION=$(VERSION) -t $(BINARY_NAME) .
	docker run --rm $(BINARY_NAME) -simulate -hit-rate $(HIT_RATE) -w /home/nonroot/examples/sample_wordlist.txt -v $(SIM_DOMAIN)

# Help command
help:
	@echo "Available commands:"
	@echo "  make build            - Build the binary"
	@echo "  make test             - Run all tests"
	@echo "  make test-short       - Run short tests"
	@echo "  make clean            - Clean build artifacts"
	@echo "  make lint             - Run linter"
	@echo "  make tidy             - go mod tidy (keeps go 1.24.2)"
	@echo "  make tui              - Launch the interactive terminal UI (no arguments needed)"
	@echo ""
	@echo "  LIVE MODE (performs real DNS queries):"
	@echo "  make run DOMAIN=x     - Build and scan DOMAIN (required, no default)"
	@echo "  make run-verbose DOMAIN=x - Build and scan DOMAIN with verbose output"
	@echo "  make run-custom DOMAIN=x  - Generate a wordlist and scan DOMAIN with it"
	@echo ""
	@echo "  SIMULATION MODE (safe, no real DNS queries):"
	@echo "  make simulate         - Run in simulation mode (no actual DNS queries)"
	@echo "  make simulate-verbose - Run in simulation mode with verbose output"
	@echo "  make simulate-custom  - Generate a wordlist and simulate scan with it"
	@echo ""
	@echo "  WORDLIST GENERATION:"
	@echo "  make wordlist-gen     - Build the wordlist generator tool"
	@echo "  make wordlist         - Generate a custom wordlist"
	@echo ""
	@echo "  DOCKER:"
	@echo "  make docker-build     - Build Docker image"
	@echo "  make docker-run DOMAIN=x  - Run Docker container (live mode)"
	@echo "  make docker-simulate  - Run Docker container in simulation mode"
	@echo ""
	@echo "IMPORTANT: Only use live mode against domains you own or have explicit permission to test."
	@echo ""
	@echo "Default parameters:"
	@echo "  WORDLIST=$(WORDLIST)"
	@echo "  DOMAIN=$(DOMAIN) (required for live targets; simulate uses $(SIM_DOMAIN))"
	@echo "  CONCURRENCY=$(CONCURRENCY)"
	@echo "  TIMEOUT=$(TIMEOUT)"
	@echo "  DNS_SERVER=$(DNS_SERVER)"
	@echo "  HIT_RATE=$(HIT_RATE)% (simulation mode only)"
	@echo ""
	@echo "Wordlist generator parameters:"
	@echo "  WL_DOMAIN=$(WL_DOMAIN)"
	@echo "  WL_COMBINE=$(WL_COMBINE)"
	@echo "  WL_OUTPUT=$(WL_OUTPUT)"
	@echo ""
	@echo "Customize parameters by setting environment variables, e.g.:"
	@echo "  DOMAIN=yourdomain.com WORDLIST=path/to/wordlist.txt make run"
	@echo "  WL_DOMAIN=yourdomain.com WL_COMBINE=dev,api,v1 make wordlist"
	@echo "  HIT_RATE=30 make simulate-verbose" 