---
layout: default
title: Architecture
---

# Architecture

This document describes the architecture of the `subenum` tool, a Go-based command-line utility for subdomain enumeration.

## 1. Overview

The `subenum` tool operates through a sequence of steps to discover valid subdomains for a given target domain:

1.  **Initialization**: Parses command-line arguments, including the target domain, path to the wordlist file, concurrency level, and DNS timeout.
2.  **Wildcard Detection**: Resolves two random subdomains to detect wildcard DNS. If detected, exits unless `-force` is set.
3.  **Wordlist Ingestion**: Reads the wordlist file into memory, deduplicating entries in a single pass.
4.  **Concurrent Resolution**: A pool of worker goroutines is established. Each worker takes a prefix from the wordlist, constructs a full subdomain string (e.g., `prefix.targetdomain.com`), and attempts to resolve it using DNS.
5.  **Output**: Resolved subdomains are printed to stdout (pipe-friendly); all progress, verbose, and diagnostic output goes to stderr.
6.  **Completion**: The tool waits for all DNS lookups to complete before exiting.

This architecture is designed to be efficient by performing multiple DNS lookups concurrently, while also providing control over the level of concurrency and timeout settings.

### Package Structure

```
main.go                        — CLI entry point (flag parsing, wiring, -tui dispatch)
internal/scan/runner.go        — Scan engine: Config, Event types, Run(ctx, cfg, events)
internal/dns/resolver.go       — ResolveDomain, ResolveDomainWithRetry, CheckWildcard
internal/dns/simulate.go       — SimulateResolution
internal/output/writer.go      — Thread-safe Writer (results→stdout, diagnostics→stderr)
internal/wordlist/reader.go    — LoadWordlist (dedup + sanitize)
internal/tui/model.go          — Root Bubble Tea model (form → scan state machine)
internal/tui/form.go           — Config form screen (textinput fields + toggles)
internal/tui/scan_view.go      — Live results screen (viewport + progress bar)
internal/tui/config.go         — Session persistence (load/save ~/.config/subenum/last.json)
```

## 2. Key Components / Modules

### 2.1. Argument Parsing

*   **Purpose**: This component is responsible for processing the command-line arguments provided by the user when `subenum` is executed. It extracts the target domain, the path to the wordlist file, the desired number of concurrent workers, and the DNS lookup timeout.
*   **Implementation**: Utilizes Go's standard `flag` package.
    *   `flag.String("w", "", "Path to the wordlist file")`: Defines the wordlist file flag.
    *   `flag.Int("t", 100, "Number of concurrent workers")`: Defines the concurrency level flag.
    *   `flag.Int("timeout", 1000, "DNS lookup timeout in milliseconds")`: Defines the DNS timeout flag.
    *   `flag.String("dns-server", DefaultDNSServer, "DNS server to use")`: Defines the custom DNS server flag.
    *   `flag.Bool("v", false, "Enable verbose output")`: Defines the verbose flag.
    *   `flag.Bool("progress", true, "Show progress during scanning")`: Defines the progress reporting flag.
    *   `flag.Bool("version", false, "Show version information")`: Defines the version flag.
    *   `flag.String("o", "", "Write results to file")`: Defines the output file flag.
    *   `flag.Int("attempts", 0, "Total DNS resolution attempts per subdomain")`: Defines the attempt count flag.
    *   `flag.Int("retries", 0, "Deprecated: alias for -attempts")`: Deprecated retry flag.
    *   `flag.Bool("force", false, "Continue scanning on wildcard DNS")`: Defines the force flag.
    *   `flag.Parse()`: Parses the provided arguments.
    *   `flag.Arg(0)`: Retrieves the positional argument (the target domain).
*   **Interactions**: The parsed values are used to configure the subsequent components, such as the Wordlist Processing and DNS Resolution Engine. Input validation is performed to ensure valid values for critical parameters like concurrency, timeout, DNS server format (validated via `validateDNSServer`), and domain syntax (validated via `validateDomain`).

### 2.2. Wordlist Processing (`internal/wordlist`)

*   **Purpose**: This component is responsible for opening, reading, sanitizing, and deduplicating the subdomain prefixes from the user-specified wordlist file.
*   **Implementation**:
    *   `wordlist.LoadWordlist(path) ([]string, int, error)`: Reads the entire file in a single pass, trims whitespace from each line, removes blank lines, and deduplicates entries using a map while preserving first-occurrence order. Returns the deduplicated slice, the count of removed duplicates, and any I/O error.
    *   `wordlist.SanitizeLine(s) string`: Trims whitespace from a single wordlist entry.
*   **Interactions**: The deduplicated entries are fed into the `subdomains` channel from a slice (no file re-read needed). The duplicate count is reported in verbose mode.

### 2.3. DNS Resolution Engine (`internal/dns`)

*   **Purpose**: This is the core component responsible for performing the actual DNS lookup for each constructed subdomain (e.g., `prefix.targetdomain.com`). It determines if a subdomain has a valid DNS record (typically A or CNAME, though the current implementation checks for any successful resolution). It also provides wildcard DNS detection.
*   **Implementation**:
    *   Function: `dns.ResolveDomain(ctx, domain, timeout, dnsServer, verbose) bool`
    *   Function: `dns.ResolveDomainWithRetry(ctx, domain, timeout, dnsServer, verbose, maxAttempts) bool` — wraps `ResolveDomain` with configurable retry logic and linear backoff between attempts.
    *   Function: `dns.CheckWildcard(ctx, domain, timeout, dnsServer) (bool, error)` — resolves two random subdomains to detect wildcard DNS records.
    *   `net.Resolver{}`: A custom DNS resolver is configured.
        *   `PreferGo: true`: Instructs the resolver to use the pure Go DNS client.
        *   `Dial func(ctx context.Context, network, address string) (net.Conn, error)`: A custom dial function is provided to control the connection to the DNS server, using the user-specified `dnsServer` address.
            *   `net.Dialer{Timeout: timeout}`: A `Dialer` is created with the user-specified timeout.
            *   `d.DialContext(ctx, "udp", dnsServer)`: Establishes a UDP connection to the configured DNS server.
    *   `resolver.LookupHost(timeoutCtx, domain)`: Performs the DNS lookup for the given domain. The context is derived from the caller via `context.WithTimeout(ctx, timeout)`, so both the per-query timeout and SIGINT cancellation are respected. It attempts to find A or AAAA records for the host.
    *   The function returns `true` if `LookupHost` returns no error (i.e., the domain resolved), and `false` otherwise.
*   **Interactions**: Workers call `dns.ResolveDomainWithRetry`, which delegates to `dns.ResolveDomain` with retry logic. It takes a fully qualified domain name, timeout duration, DNS server address, verbose flag, and retry count as input. It outputs a boolean indicating whether the domain resolved successfully. The result is used to decide if the domain should be printed to the console and/or written to the output file.

### 2.4. Concurrency Management (`internal/scan`)

*   **Purpose**: To efficiently perform DNS lookups for a large number of potential subdomains, `subenum` employs a worker pool pattern. This allows multiple DNS queries to be in flight concurrently, significantly speeding up the enumeration process compared to sequential lookups.
*   **Implementation**: The worker pool logic lives in `internal/scan/runner.go` as `scan.Run(ctx, cfg, events)`. Both the CLI (`run()` in `main.go`) and the TUI (`internal/tui`) call this function.
    *   **`scan.Config`**: A struct carrying all scan parameters (domain, entries slice, concurrency, timeout, DNS server, simulate flag, etc.).
    *   **`scan.Event` / `scan.EventKind`**: Typed events emitted on a `chan<- scan.Event` — `EventResult`, `EventProgress`, `EventWildcard`, `EventError`, `EventDone`.
    *   **`subdomains := make(chan string)`**: An internal channel acts as a work queue. Entries from the pre-loaded wordlist slice are fed into it.
    *   **`var wg sync.WaitGroup`**: A `sync.WaitGroup` waits for all worker goroutines to finish.
    *   **Worker Goroutines Loop**: `cfg.Concurrency` goroutines are launched. Each reads prefixes from the channel, constructs the full domain, and calls `dns.ResolveDomainWithRetry()` (or `dns.SimulateResolution()` in simulate mode).
    *   **Progress ticker**: A separate goroutine fires every second and emits `EventProgress` events so callers can update their display.
    *   **Closing the Channel**: After all entries are sent, the channel is closed, signalling workers to exit. `wg.Wait()` blocks until all workers are done, then `EventDone` is emitted.
*   **Interactions**: `scan.Run` is the single entry point for scanning used by both the CLI output pipeline and the Bubble Tea TUI. It decouples the scan engine from any specific display layer.

### 2.5. Output Formatting (`internal/output`)

*   **Purpose**: Thread-safe output that keeps stdout pipe-clean. Resolved subdomains go to stdout; everything else (progress, verbose diagnostics, errors) goes to stderr.
*   **Implementation**:
    *   `output.Writer` struct with mutex-protected methods:
        *   `Result(domain)` — prints `Found: <domain>` to stdout (and to the output file if configured).
        *   `Progress(pct, processed, total, found)` — writes a carriage-return progress line to stderr.
        *   `Info(format, args...)` — writes an informational line to stderr.
        *   `Error(format, args...)` — writes an error line to stderr.
    *   **Verbose Output** (when `-v` flag is enabled):
        *   Configuration summary, per-query DNS resolution info, and final scan statistics — all via `Info` to stderr.
    *   **Progress Reporting** (when `-progress` flag is enabled):
        *   A dedicated goroutine using a 2-second ticker calls `Progress` on stderr.
*   **Interactions**: All components route output through the `Writer`. Since results are the only thing on stdout, piping (`| cut -d' ' -f2`) works without `-progress=false`.

### 2.6. Progress Monitoring

*   **Purpose**: This component tracks the progress of the subdomain enumeration process and provides real-time feedback to the user via stderr.
*   **Implementation**:
    *   **Total Count**: The total word count comes from the length of the deduplicated wordlist slice (no separate file pass needed).
    *   **Atomic Counters**:
        *   `processedWords`: An atomic counter that's incremented each time a subdomain is checked.
        *   `foundSubdomains`: An atomic counter that's incremented each time a valid subdomain is found.
    *   **Progress Display** (on stderr):
        *   A dedicated goroutine using a ticker (running every 2 seconds) calls `Writer.Progress`
        *   Uses `\r` carriage return to update the same line repeatedly
        *   Shows percentage completion, processed count, and found count
*   **Interactions**: The Progress Monitoring component works alongside the worker goroutines, using atomic operations to safely track counts across multiple goroutines. Writing to stderr keeps stdout pipe-clean.

### 2.7. Session Persistence (`internal/tui/config.go`)

*   **Purpose**: Remember the last-used TUI form values across sessions so users don't have to re-type domain, wordlist path, and scan parameters every time.
*   **Implementation**:
    *   `savedConfig` struct mirrors `formValues` with JSON tags.
    *   `configPath()` — returns `os.UserConfigDir()/subenum/last.json` (e.g. `~/.config/subenum/last.json` on Linux/macOS, `%AppData%\subenum\last.json` on Windows).
    *   `saveConfig(fv formValues) error` — marshals `formValues` to JSON and writes it atomically with `os.WriteFile`. Called in `beginScan()` immediately before launching the scan goroutine. Errors are silently discarded so a write failure never blocks the scan.
    *   `loadSavedConfig() (savedConfig, bool)` — reads and unmarshals the file. Returns `false` if the file doesn't exist or is unreadable, causing `newFormModel` to fall back to hardcoded defaults.
*   **Interactions**: `tui.New()` calls `loadSavedConfig()` on startup and passes the result to `newFormModel`. The `r` keybind (new scan) also calls `loadSavedConfig()` so the form is pre-filled with the values from the scan that just completed.

## 3. Data Flow

The flow of data through the `subenum` application can be summarized as follows:

1.  **Input**: The user provides command-line arguments: the target domain, the path to a wordlist file (`-w`), a concurrency level (`-t`), a DNS timeout (`-timeout`), a DNS server (`-dns-server`), attempts (`-attempts`), and flags for verbose mode (`-v`), progress reporting (`-progress`), and force mode (`-force`).
2.  **Configuration**: These arguments are parsed and validated by the **Argument Parsing** component and used to configure the tool's behavior.
3.  **Wildcard Detection**: Two random subdomains are resolved against the target domain. If both (or either) resolve, wildcard DNS is detected. The scan aborts unless `-force` is set.
4.  **Wordlist Loading**: `wordlist.LoadWordlist` reads the file in a single pass, sanitizes lines, and deduplicates entries into a slice.
    *   Each entry is sent into the `subdomains` channel from the in-memory slice.
5.  **Work Distribution**: The `subdomains` channel acts as a queue for the **Concurrency Management (Worker Pool)** component.
    *   Worker goroutines (number determined by the `-t` flag) pick up these prefixes from the channel.
6.  **Subdomain Construction**: Each worker goroutine takes a `subdomainPrefix` and concatenates it with the `targetDomain` (e.g., `subdomainPrefix + "." + targetDomain`) to form a `fullDomain` string.
7.  **DNS Lookup**: The `fullDomain` string, the `timeout` value, and the DNS server are passed to `dns.ResolveDomainWithRetry` within the **DNS Resolution Engine**.
    *   `dns.ResolveDomain` attempts to resolve the `fullDomain`.
    *   It returns `true` if the domain resolves successfully, `false` otherwise.
    *   If verbose mode is enabled, it also prints detailed information about the resolution attempt.
8.  **Output Generation**: 
    *   If the resolution returns `true`, the worker goroutine uses the **Output Formatting** component to print the `fullDomain` to the standard output.
    *   The atomic counter for found subdomains is incremented.
9.  **Progress Tracking**: After each DNS lookup:
    *   The atomic counter for processed entries is incremented.
    *   If progress reporting is enabled, a separate goroutine periodically updates the progress display.
10. **Loop/Termination**:
    *   Worker goroutines loop back to step 5 to pick up more work from the `subdomains` channel.
    *   Once all prefixes are read from the wordlist, the **Wordlist Processing** component closes the `subdomains` channel.
    *   Worker goroutines eventually terminate after the channel is closed and all in-flight DNS lookups are complete.
    *   The main goroutine, which is waiting on a `sync.WaitGroup`, unblocks.
    *   If verbose mode is enabled, a final summary is printed.
    *   The program exits.

Visually, this can be seen as:

`User Input -> Argument Parser -> [Wordlist File] -> Wordlist Processor -> scan.Run() -> Worker Goroutines -> DNS Resolver -> Event Channel -> Output (if resolved)`

## 4. Error Handling Strategy

`subenum` handles different types of errors at various stages of its operation:

### 4.1. User Input Errors

*   **Missing Required Arguments**: When the user doesn't provide a wordlist file (`-w` flag) or a target domain, the tool prints a usage message followed by the description of all flags, and then exits with a non-zero status code (`os.Exit(1)`).
*   **Validation**: The tool validates:
    *   Concurrency level and timeout must be positive integers.
    *   DNS server must be a valid `ip:port` format with proper IP address and port range (1-65535), validated by `validateDNSServer`.
    *   Target domain must conform to DNS naming rules, validated by `validateDomain`.
    *   Hit rate (simulation mode) must be 1-100.
    *   Retry count must be at least 1.

### 4.2. File Operation Errors

*   **File Not Found or Can't Be Read**: If the wordlist file specified by the `-w` flag cannot be opened (e.g., it doesn't exist, permissions are insufficient, or the path is invalid), the tool prints an error message (`fmt.Printf("Error opening wordlist file: %v\n", err)`) and exits with a non-zero status code (`os.Exit(1)`).
*   **File Reading Errors**: If an error occurs while reading the file (e.g., the scanner encounters an error), the tool prints an error message (`fmt.Printf("Error reading wordlist file: %v\n", err)`) but does not exit immediately. It continues to process any words it has already read before the error.

### 4.3. DNS Resolution Errors

*   **Lookup Failure**: When a DNS lookup fails (e.g., the subdomain doesn't exist, there's a DNS server problem, or the timeout is exceeded), the tool silently ignores the failure and doesn't print any message. This is by design, as the tool is only interested in reporting successful subdomain resolutions.
*   **Timeout Handling**: The user-specified timeout (`-timeout` flag) is used to limit how long each DNS query can take. If a query exceeds this timeout, it's considered a failure and is treated as if the subdomain doesn't exist. This prevents the tool from hanging indefinitely on slow or unresponsive DNS servers.

### 4.4. Concurrency-Related Issues

*   **Channel Operations**: The tool uses a channel (`subdomains`) to pass work between the wordlist reading goroutine and the worker goroutines. No explicit error handling is implemented for channel operations, as Go's channel semantics ensure that operations like closing an already closed channel would panic. This is avoided by design in the current implementation.
*   **Worker Goroutine Errors**: Each worker goroutine processes DNS lookups independently. If an error occurs within a worker (outside of the expected DNS resolution failures), it can cause the entire goroutine to terminate. The current implementation doesn't have specific handling for such scenarios.

### 4.5. Graceful Shutdown

The tool listens for `SIGINT` and `SIGTERM` signals. Upon receiving an interrupt, it cancels the work context, drains in-flight workers, and exits cleanly with a summary of results processed so far.

### 4.6. Output File Support

When the `-o` flag is provided, resolved subdomains are written to the specified file (one per line) in addition to stdout. A mutex protects concurrent writes to both stdout and the output file.

### 4.7. Retry Mechanism

The `-attempts` flag (default: 1) controls the total number of DNS resolution attempts per subdomain. A value of 1 means no retries. A short linear backoff delay is applied between attempts to handle transient DNS failures. The deprecated `-retries` flag is still accepted as an alias but prints a warning to stderr.