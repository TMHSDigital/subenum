FROM golang:1.22-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum first to leverage Docker cache
COPY go.mod ./

# Copy source code
COPY main.go ./
COPY main_test.go ./

# Build the binary with optimizations
RUN CGO_ENABLED=0 GOOS=linux go build -o subenum -ldflags="-w -s" .

# Use a minimal alpine image for the final container
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy binary from builder stage
COPY --from=builder /app/subenum .

# Copy examples directory with wordlists
COPY examples/ ./examples/

# Create volume mount point for custom wordlists and output
VOLUME ["/data"]

ENTRYPOINT ["./subenum"]

# Default command - shows help
CMD ["-version"]

LABEL org.opencontainers.image.title="subenum"
LABEL org.opencontainers.image.description="A Go-based CLI tool for subdomain enumeration"
LABEL org.opencontainers.image.source="https://github.com/yourusername/subenum"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.documentation="https://github.com/yourusername/subenum/blob/main/README.md"
LABEL org.opencontainers.image.vendor="Educational Use Only"
LABEL org.opencontainers.image.usage="For educational and legitimate security testing purposes only" 