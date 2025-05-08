#!/bin/bash

# multi_domain_scan.sh
# Example script that demonstrates scanning multiple domains with subenum
#
# IMPORTANT LEGAL NOTICE:
# This script is provided for educational and legitimate security testing purposes only.
# You MUST have proper authorization before using this script against any domain.
# Unauthorized scanning may violate laws and regulations in your jurisdiction.
# See the LICENSE file in the project root for full terms of use.

# Path to the subenum executable (adjust if necessary)
SUBENUM_PATH="../subenum"

# Path to the wordlist
WORDLIST="./sample_wordlist.txt"

# Concurrency and timeout settings
CONCURRENCY=100
TIMEOUT=1000  # ms

# Check if domains list file is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <domains_list_file>"
    echo "Example: $0 domains.txt"
    exit 1
fi

DOMAINS_FILE=$1

# Check if the domains file exists
if [ ! -f "$DOMAINS_FILE" ]; then
    echo "Error: Domains file '$DOMAINS_FILE' not found!"
    exit 1
fi

# Check if the subenum executable exists
if [ ! -f "$SUBENUM_PATH" ]; then
    echo "Error: subenum executable not found at '$SUBENUM_PATH'"
    echo "Build the project first with 'go build' in the project root directory"
    exit 1
fi

# Create output directory
OUTPUT_DIR="./results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"
echo "Results will be saved to: $OUTPUT_DIR"

# Process each domain
while IFS= read -r domain || [ -n "$domain" ]; do
    # Skip empty lines and comments
    [[ "$domain" =~ ^[[:space:]]*$ || "$domain" =~ ^# ]] && continue
    
    # Trim whitespace
    domain=$(echo "$domain" | tr -d '[:space:]')
    
    echo "======================================"
    echo "Scanning domain: $domain"
    echo "======================================"
    
    # Run subenum and save output to file
    output_file="$OUTPUT_DIR/${domain}.txt"
    $SUBENUM_PATH -w "$WORDLIST" -t "$CONCURRENCY" -timeout "$TIMEOUT" "$domain" | tee "$output_file"
    
    # Count results
    count=$(grep -c "Found:" "$output_file")
    echo "Found $count subdomains for $domain"
    echo "Results saved to: $output_file"
    echo ""
done < "$DOMAINS_FILE"

echo "All scans completed. Results saved to: $OUTPUT_DIR"

# Optional: Generate a summary file
echo "Generating summary..."
summary_file="$OUTPUT_DIR/_summary.txt"
echo "SUBDOMAIN ENUMERATION SUMMARY" > "$summary_file"
echo "Generated on: $(date)" >> "$summary_file"
echo "----------------------------------------" >> "$summary_file"

for result_file in "$OUTPUT_DIR"/*.txt; do
    # Skip the summary file itself
    [[ "$result_file" == "$summary_file" ]] && continue
    
    domain=$(basename "$result_file" .txt)
    count=$(grep -c "Found:" "$result_file")
    echo "$domain: $count subdomains" >> "$summary_file"
done

echo "Summary saved to: $summary_file" 