#!/bin/bash

# demo.sh - A demonstration script for the subenum toolkit
# This script showcases a complete workflow with the subenum tool and related utilities

# IMPORTANT: This script is for EDUCATIONAL PURPOSES ONLY
# Only use against domains you own or have explicit permission to test

# Ensure we're in the project root directory
cd "$(dirname "$0")/.."

# Parse arguments
SIMULATION_MODE=false
while getopts ":s" opt; do
  case ${opt} in
    s )
      SIMULATION_MODE=true
      ;;
    \? )
      echo "Usage: $0 [-s]"
      echo "  -s : Run in simulation mode (no actual DNS queries)"
      exit 1
      ;;
  esac
done

echo "============================================================="
echo "  SUBENUM DEMONSTRATION WORKFLOW - EDUCATIONAL USE ONLY"
echo "============================================================="
echo ""

if [ "$SIMULATION_MODE" = true ]; then
    echo "Running in SIMULATION MODE - No actual DNS queries will be performed"
    echo "This is completely safe and legal to run."
    echo ""
    SIMULATE_FLAG="-simulate"
else
    echo "⚠️  IMPORTANT: Running in LIVE mode - Actual DNS queries will be performed"
    echo "⚠️  Only proceed if you have explicit permission to scan the target domain"
    echo "⚠️  To run in safe simulation mode instead, use: $0 -s"
    echo ""
    echo "Press Ctrl+C now to cancel, or Enter to continue..."
    read -r
    SIMULATE_FLAG=""
fi

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Set target domain (EXAMPLE ONLY - replace with authorized domain)
TARGET_DOMAIN="example.com"

# Setup phase
echo -e "${YELLOW}[1/7] Building subenum tool...${NC}"
go build -buildvcs=false -o subenum
echo -e "${GREEN}✓ Build complete${NC}"
echo ""

# Build wordlist generator
echo -e "${YELLOW}[2/7] Building wordlist generator...${NC}"
go build -buildvcs=false -o tools/wordlist-gen tools/wordlist-gen.go
echo -e "${GREEN}✓ Build complete${NC}"
echo ""

# Generate a custom wordlist
echo -e "${YELLOW}[3/7] Generating domain-specific wordlist...${NC}"
tools/wordlist-gen -domain $TARGET_DOMAIN -combine "dev,api,staging,test,v1,v2" -o demo-wordlist.txt
echo -e "${GREEN}✓ Custom wordlist generated${NC}"
echo ""

# Basic scan
echo -e "${YELLOW}[4/7] Running basic scan...${NC}"
echo -e "${BLUE}Command: ./subenum $SIMULATE_FLAG -w examples/sample_wordlist.txt $TARGET_DOMAIN${NC}"
echo "Press Enter to continue..."
read -r
./subenum $SIMULATE_FLAG -w examples/sample_wordlist.txt $TARGET_DOMAIN
echo -e "${GREEN}✓ Basic scan complete${NC}"
echo ""

# Advanced scan with custom options
echo -e "${YELLOW}[5/7] Running advanced scan with custom options...${NC}"
if [ "$SIMULATION_MODE" = true ]; then
    echo -e "${BLUE}Command: ./subenum $SIMULATE_FLAG -hit-rate 30 -w demo-wordlist.txt -t 200 -timeout 1500 -v $TARGET_DOMAIN${NC}"
    echo "Press Enter to continue..."
    read -r
    ./subenum $SIMULATE_FLAG -hit-rate 30 -w demo-wordlist.txt -t 200 -timeout 1500 -v $TARGET_DOMAIN
else
    echo -e "${BLUE}Command: ./subenum $SIMULATE_FLAG -w demo-wordlist.txt -t 200 -timeout 1500 -dns-server 1.1.1.1:53 -v $TARGET_DOMAIN${NC}"
    echo "Press Enter to continue..."
    read -r
    ./subenum $SIMULATE_FLAG -w demo-wordlist.txt -t 200 -timeout 1500 -dns-server 1.1.1.1:53 -v $TARGET_DOMAIN
fi
echo -e "${GREEN}✓ Advanced scan complete${NC}"
echo ""

# Docker showcase
echo -e "${YELLOW}[6/7] Demonstrating Docker usage...${NC}"
if [ "$SIMULATION_MODE" = true ]; then
    echo -e "${BLUE}Command: docker build -t subenum . && docker run --rm subenum -simulate -version${NC}"
else
    echo -e "${BLUE}Command: docker build -t subenum . && docker run --rm subenum -version${NC}"
fi
echo "Press Enter to continue (skip with Ctrl+C)..."
read -r
if [ "$SIMULATION_MODE" = true ]; then
    docker build -t subenum . && docker run --rm subenum -simulate -version
else
    docker build -t subenum . && docker run --rm subenum -version
fi
echo -e "${GREEN}✓ Docker demonstration complete${NC}"
echo ""

# Cleanup
echo -e "${YELLOW}[7/7] Cleaning up...${NC}"
rm -f demo-wordlist.txt
echo -e "${GREEN}✓ Cleanup complete${NC}"
echo ""

echo -e "${GREEN}==============================================================${NC}"
echo -e "${GREEN}  DEMONSTRATION COMPLETE                                      ${NC}"
echo -e "${GREEN}==============================================================${NC}"
echo ""
echo -e "${YELLOW}Key takeaways:${NC}"
echo "• The subenum tool provides efficient subdomain enumeration"
echo "• Custom wordlists can be generated based on domain-specific terms"
echo "• Multiple configuration options provide flexibility for different scenarios"
echo "• Simulation mode allows safe testing without actual DNS queries"
echo "• Docker support enables containerized usage"
echo ""
echo -e "${RED}IMPORTANT REMINDER:${NC}"
if [ "$SIMULATION_MODE" = true ]; then
    echo "Simulation mode was used - no actual DNS queries were performed."
else
    echo "This tool is for educational and legitimate security testing purposes only."
    echo "Always ensure you have explicit permission to scan any domain."
fi
echo "" 