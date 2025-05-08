# Architecture

This document describes the architecture of the `subenum` tool, a Go-based command-line utility for subdomain enumeration.

## 1. Overview

The `subenum` tool operates through a sequence of steps to discover valid subdomains for a given target domain:

1.  **Initialization**: Parses command-line arguments, including the target domain, path to the wordlist file, concurrency level, and DNS timeout.
2.  **Wordlist Ingestion**: Opens and reads the specified wordlist file, preparing a list of potential subdomain prefixes.
3.  **Concurrent Resolution**: A pool of worker goroutines is established. Each worker takes a prefix from the wordlist, constructs a full subdomain string (e.g., `prefix.targetdomain.com`), and attempts to resolve it using DNS.
4.  **Output**: If a subdomain is successfully resolved (i.e., a DNS record is found), it is printed to the standard output.
5.  **Completion**: The tool waits for all DNS lookups to complete before exiting.

This architecture is designed to be efficient by performing multiple DNS lookups concurrently, while also providing control over the level of concurrency and timeout settings.

## 2. Key Components / Modules

*(Details to be added regarding components, data flow, concurrency, etc.)*

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
    *   `flag.Parse()`: Parses the provided arguments.
    *   `flag.Arg(0)`: Retrieves the positional argument (the target domain).
*   **Interactions**: The parsed values are used to configure the subsequent components, such as the Wordlist Processing and DNS Resolution Engine. Input validation is also performed to ensure valid values for critical parameters like concurrency and timeout.

### 2.2. Wordlist Processing

*   **Purpose**: This component is responsible for opening and reading the subdomain prefixes from the user-specified wordlist file. Each line in the file is treated as a potential subdomain prefix.
*   **Implementation**:
    *   `os.Open(*wordlistFile)`: Opens the file specified by the `-w` flag.
    *   `bufio.NewScanner(file)`: Creates a new scanner to read the file content line by line, which is efficient for large files.
    *   `scanner.Scan()`: Advances the scanner to the next line.
    *   `scanner.Text()`: Retrieves the current line (subdomain prefix) as a string.
*   **Interactions**: The prefixes read from the wordlist are sent to the `subdomains` channel, which is consumed by the worker goroutines in the Concurrency Management component. Error handling is in place for issues like the file not being found or being unreadable.

### 2.3. DNS Resolution Engine

*   **Purpose**: This is the core component responsible for performing the actual DNS lookup for each constructed subdomain (e.g., `prefix.targetdomain.com`). It determines if a subdomain has a valid DNS record (typically A or CNAME, though the current implementation checks for any successful resolution).
*   **Implementation**:
    *   Function: `resolveDomain(domain string, timeout time.Duration) bool`
    *   `net.Resolver{}`: A custom DNS resolver is configured.
        *   `PreferGo: true`: Instructs the resolver to use the pure Go DNS client.
        *   `Dial func(ctx context.Context, network, address string) (net.Conn, error)`: A custom dial function is provided to control the connection to the DNS server. This allows for setting a specific timeout for the dial operation and for specifying the DNS server to use (currently hardcoded to Google's public DNS `8.8.8.8:53`).
            *   `net.Dialer{Timeout: timeout}`: A `Dialer` is created with the user-specified timeout.
            *   `d.DialContext(ctx, "udp", "8.8.8.8:53")`: Establishes a UDP connection to the DNS server.
    *   `resolver.LookupHost(context.Background(), domain)`: Performs the DNS lookup for the given domain. It attempts to find A or AAAA records for the host.
    *   The function returns `true` if `LookupHost` returns no error (i.e., the domain resolved), and `false` otherwise.
*   **Interactions**: This function is called by each worker goroutine. It takes a fully qualified domain name and the timeout duration as input. It outputs a boolean indicating whether the domain resolved successfully. The result is used to decide if the domain should be printed to the console.

### 2.4. Concurrency Management (Worker Pool)

*   **Purpose**: To efficiently perform DNS lookups for a large number of potential subdomains, `subenum` employs a worker pool pattern. This allows multiple DNS queries to be in flight concurrently, significantly speeding up the enumeration process compared to sequential lookups.
*   **Implementation**:
    *   **`subdomains := make(chan string)`**: A buffered channel (though currently unbuffered in `main.go`, could be buffered for performance tuning) is created to act as a work queue. Subdomain prefixes read from the wordlist are sent to this channel.
    *   **`var wg sync.WaitGroup`**: A `sync.WaitGroup` is used to wait for all worker goroutines to complete their tasks before the main function exits.
    *   **Worker Goroutines Loop (`for i := 0; i < *concurrency; i++`)**: A loop launches a number of goroutines specified by the `-t` (concurrency) flag. Each goroutine acts as a worker.
        *   `wg.Add(1)`: Increments the `WaitGroup` counter for each worker started.
        *   `go func() { ... }()`: Each worker runs in its own goroutine.
        *   `defer wg.Done()`: Decrements the `WaitGroup` counter when the goroutine exits.
        *   `for subdomainPrefix := range subdomains { ... }`: Each worker continuously reads subdomain prefixes from the `subdomains` channel until the channel is closed. For each prefix, it constructs the full domain and calls `resolveDomain()`.
    *   **Closing the Channel (`close(subdomains)`)**: After all subdomain prefixes from the wordlist have been sent to the `subdomains` channel, the channel is closed. This signals to the worker goroutines that no more work will be added.
    *   **Waiting for Completion (`wg.Wait()`)**: The main goroutine blocks until all worker goroutines have called `wg.Done()`, ensuring all lookups are finished.
*   **Interactions**: This component orchestrates the parallel execution of DNS lookups. It receives subdomain prefixes from the Wordlist Processing component (via the `subdomains` channel) and utilizes the DNS Resolution Engine within each worker goroutine. The number of workers is controlled by the Argument Parsing component.

### 2.5. Output Formatting

*   **Purpose**: This component is responsible for presenting the successfully resolved subdomains and other information to the user.
*   **Implementation**:
    *   **Standard Output**: 
        *   `fmt.Printf("Found: %s\n", fullDomain)`: When a worker goroutine successfully resolves a subdomain (i.e., `resolveDomain()` returns `true`), this function is used to print the discovered subdomain to the standard output.
    *   **Verbose Output** (when `-v` flag is enabled):
        *   Initial configuration summary (domain, wordlist, concurrency, timeout, DNS server)
        *   Detailed DNS resolution information for each lookup, including success/failure status, IP addresses, and timing information
        *   Final scan summary with statistics
    *   **Progress Reporting** (when `-progress` flag is enabled):
        *   A separate goroutine displays and updates a progress line showing:
            *   Percentage completion based on processed subdomains
            *   Count of processed entries
            *   Count of successfully resolved subdomains
*   **Interactions**: The Output Formatting component interacts with all other components, presenting information from various stages of the scanning process. The level of detail is controlled by command-line flags. Since multiple goroutines can print concurrently, atomic operations are used to ensure thread-safe counts for progress reporting.

### 2.6. Progress Monitoring

*   **Purpose**: This component tracks the progress of the subdomain enumeration process and provides real-time feedback to the user.
*   **Implementation**:
    *   **Line Counting**: When the `-progress` flag is enabled, the wordlist file is first scanned to count the total number of lines, providing the denominator for percentage calculations.
    *   **Atomic Counters**:
        *   `processedWords`: An atomic counter that's incremented each time a subdomain is checked.
        *   `foundSubdomains`: An atomic counter that's incremented each time a valid subdomain is found.
    *   **Progress Display**:
        *   A dedicated goroutine using a ticker (running every 2 seconds) to update the progress display
        *   Uses `\r` carriage return to update the same line repeatedly
        *   Shows percentage completion, processed count, and found count
*   **Interactions**: The Progress Monitoring component works alongside the worker goroutines, using atomic operations to safely track counts across multiple goroutines.

## 3. Data Flow

The flow of data through the `subenum` application can be summarized as follows:

1.  **Input**: The user provides command-line arguments: the target domain, the path to a wordlist file (`-w`), a concurrency level (`-t`), a DNS timeout (`-timeout`), a DNS server (`-dns-server`), and flags for verbose mode (`-v`) and progress reporting (`-progress`).
2.  **Configuration**: These arguments are parsed and validated by the **Argument Parsing** component and used to configure the tool's behavior.
3.  **Initialization**: If progress reporting is enabled, the wordlist file is scanned once to count total entries.
4.  **Wordlist Reading**: The **Wordlist Processing** component opens the specified wordlist file.
    *   It reads the file line by line.
    *   Each line (a subdomain prefix string) is sent as a message into the `subdomains` channel.
5.  **Work Distribution**: The `subdomains` channel acts as a queue for the **Concurrency Management (Worker Pool)** component.
    *   Worker goroutines (number determined by the `-t` flag) pick up these prefixes from the channel.
6.  **Subdomain Construction**: Each worker goroutine takes a `subdomainPrefix` and concatenates it with the `targetDomain` (e.g., `subdomainPrefix + "." + targetDomain`) to form a `fullDomain` string.
7.  **DNS Lookup**: The `fullDomain` string, the `timeout` value, and the DNS server are passed to the `resolveDomain` function within the **DNS Resolution Engine**.
    *   The `resolveDomain` function attempts to resolve the `fullDomain`.
    *   It returns `true` if the domain resolves successfully, `false` otherwise.
    *   If verbose mode is enabled, it also prints detailed information about the resolution attempt.
8.  **Output Generation**: 
    *   If `resolveDomain` returns `true`, the worker goroutine uses the **Output Formatting** component to print the `fullDomain` to the standard output.
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

`User Input -> Argument Parser -> [Wordlist File] -> Wordlist Processor -> subdomains channel -> Worker Goroutines -> DNS Resolver -> Output (if resolved)`

## 4. Error Handling Strategy

`subenum` handles different types of errors at various stages of its operation:

### 4.1. User Input Errors

*   **Missing Required Arguments**: When the user doesn't provide a wordlist file (`-w` flag) or a target domain, the tool prints a usage message (`fmt.Println("Usage: subenum -w <wordlist_file> <domain>")`) followed by the description of all flags, and then exits with a non-zero status code (`os.Exit(1)`).
*   **Validation**: Currently, the tool performs minimal validation of the input arguments. The domain and wordlist file must be provided, but there is no validation of flag values (e.g., checking if the concurrency level or timeout is a positive number).

### 4.2. File Operation Errors

*   **File Not Found or Can't Be Read**: If the wordlist file specified by the `-w` flag cannot be opened (e.g., it doesn't exist, permissions are insufficient, or the path is invalid), the tool prints an error message (`fmt.Printf("Error opening wordlist file: %v\n", err)`) and exits with a non-zero status code (`os.Exit(1)`).
*   **File Reading Errors**: If an error occurs while reading the file (e.g., the scanner encounters an error), the tool prints an error message (`fmt.Printf("Error reading wordlist file: %v\n", err)`) but does not exit immediately. It continues to process any words it has already read before the error.

### 4.3. DNS Resolution Errors

*   **Lookup Failure**: When a DNS lookup fails (e.g., the subdomain doesn't exist, there's a DNS server problem, or the timeout is exceeded), the tool silently ignores the failure and doesn't print any message. This is by design, as the tool is only interested in reporting successful subdomain resolutions.
*   **Timeout Handling**: The user-specified timeout (`-timeout` flag) is used to limit how long each DNS query can take. If a query exceeds this timeout, it's considered a failure and is treated as if the subdomain doesn't exist. This prevents the tool from hanging indefinitely on slow or unresponsive DNS servers.

### 4.4. Concurrency-Related Issues

*   **Channel Operations**: The tool uses a channel (`subdomains`) to pass work between the wordlist reading goroutine and the worker goroutines. No explicit error handling is implemented for channel operations, as Go's channel semantics ensure that operations like closing an already closed channel would panic. This is avoided by design in the current implementation.
*   **Worker Goroutine Errors**: Each worker goroutine processes DNS lookups independently. If an error occurs within a worker (outside of the expected DNS resolution failures), it can cause the entire goroutine to terminate. The current implementation doesn't have specific handling for such scenarios.

### 4.5. Potential Improvements

*   **Input Validation**: Add more thorough validation of command-line arguments, including:
    *   Checking that the concurrency level is positive.
    *   Validating that the timeout value is reasonable.
    *   Verifying that the domain adheres to DNS naming rules.
*   **Verbose Mode**: Implement a verbose mode (e.g., `-v` flag) that would print more information, including errors during DNS lookups, to help with debugging.
*   **Graceful Handling of DNS Server Issues**: Add better handling of DNS server problems, possibly including retry mechanisms or fall-back to alternative DNS servers.
*   **Progress Reporting**: Provide information about the progress of the enumeration to give the user feedback on long-running scans. 