.PHONY: build test clean lint run docker-build docker-run wordlist wordlist-gen simulate simulate-verbose

# Default Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOVET=$(GOCMD) vet
BINARY_NAME=subenum
WORDLIST_GEN=wordlist-gen

# Default run parameters - CHANGE THESE!
WORDLIST=examples/sample_wordlist.txt
DOMAIN=example.com # Always use authorized domains
CONCURRENCY=100
TIMEOUT=1000
DNS_SERVER=8.8.8.8:53

# Simulation parameters
HIT_RATE=15

# Wordlist generator parameters
WL_DOMAIN=$(DOMAIN)
WL_COMBINE=dev,staging,test,api
WL_OUTPUT=custom-wordlist.txt

all: build

build:
	$(GOBUILD) -buildvcs=false -o $(BINARY_NAME)

test:
	$(GOTEST) -v ./...

test-short:
	$(GOTEST) -v ./... -short

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME).exe
	rm -f tools/$(WORDLIST_GEN)

lint:
	golangci-lint run

# Build wordlist generator
wordlist-gen:
	$(GOBUILD) -buildvcs=false -o tools/$(WORDLIST_GEN) tools/wordlist-gen.go

# Generate a custom wordlist
wordlist: wordlist-gen
	tools/$(WORDLIST_GEN) -domain $(WL_DOMAIN) -combine $(WL_COMBINE) -o $(WL_OUTPUT)
	@echo "Generated wordlist: $(WL_OUTPUT)"
	@echo "Use it with: make WORDLIST=$(WL_OUTPUT) DOMAIN=$(WL_DOMAIN) run-verbose"

# Run with default parameters
run: build
	./$(BINARY_NAME) -w $(WORDLIST) -t $(CONCURRENCY) -timeout $(TIMEOUT) -dns-server $(DNS_SERVER) $(DOMAIN)

# Run with verbose output
run-verbose: build
	./$(BINARY_NAME) -w $(WORDLIST) -t $(CONCURRENCY) -timeout $(TIMEOUT) -dns-server $(DNS_SERVER) -v $(DOMAIN)

# Run in simulation mode (safe, no actual DNS queries)
simulate: build
	./$(BINARY_NAME) -simulate -hit-rate $(HIT_RATE) -w $(WORDLIST) -t $(CONCURRENCY) -timeout $(TIMEOUT) $(DOMAIN)

# Run in simulation mode with verbose output (safe, no actual DNS queries)
simulate-verbose: build
	./$(BINARY_NAME) -simulate -hit-rate $(HIT_RATE) -w $(WORDLIST) -t $(CONCURRENCY) -timeout $(TIMEOUT) -v $(DOMAIN)

# Generate a wordlist and use it with simulation mode
simulate-custom: wordlist build
	./$(BINARY_NAME) -simulate -hit-rate $(HIT_RATE) -w $(WL_OUTPUT) -t $(CONCURRENCY) -timeout $(TIMEOUT) -v $(WL_DOMAIN)

# Generate a wordlist and immediately use it
run-custom: wordlist build
	./$(BINARY_NAME) -w $(WL_OUTPUT) -t $(CONCURRENCY) -timeout $(TIMEOUT) -dns-server $(DNS_SERVER) -v $(WL_DOMAIN)

# Docker commands
docker-build:
	docker build -t $(BINARY_NAME) .

docker-run:
	docker run --rm -v $(PWD)/data:/data $(BINARY_NAME) -w /data/wordlist.txt -v example.com

# Run Docker in simulation mode (completely safe)
docker-simulate:
	docker build -t $(BINARY_NAME) .
	docker run --rm $(BINARY_NAME) -simulate -hit-rate $(HIT_RATE) -w /root/examples/sample_wordlist.txt -v example.com

# Help command
help:
	@echo "Available commands:"
	@echo "  make build            - Build the binary"
	@echo "  make test             - Run all tests"
	@echo "  make test-short       - Run short tests"
	@echo "  make clean            - Clean build artifacts"
	@echo "  make lint             - Run linter"
	@echo ""
	@echo "  LIVE MODE (performs real DNS queries):"
	@echo "  make run              - Build and run with default parameters"
	@echo "  make run-verbose      - Build and run with verbose output"
	@echo "  make run-custom       - Generate a wordlist and scan with it"
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
	@echo "  make docker-run       - Run Docker container (live mode)"
	@echo "  make docker-simulate  - Run Docker container in simulation mode"
	@echo ""
	@echo "IMPORTANT: Only use live mode against domains you own or have explicit permission to test."
	@echo ""
	@echo "Default parameters:"
	@echo "  WORDLIST=$(WORDLIST)"
	@echo "  DOMAIN=$(DOMAIN) (EDUCATIONAL EXAMPLE ONLY)"
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