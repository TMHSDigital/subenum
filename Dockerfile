FROM golang:1.24.2-alpine AS builder

WORKDIR /app

# Copy module files first and download deps to leverage Docker layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY main.go ./
COPY internal/ ./internal/

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
LABEL org.opencontainers.image.source="https://github.com/TMHSDigital/subenum"
LABEL org.opencontainers.image.licenses="GPL-3.0"
LABEL org.opencontainers.image.documentation="https://github.com/TMHSDigital/subenum/blob/main/README.md"
LABEL org.opencontainers.image.vendor="Educational Use Only"
LABEL org.opencontainers.image.usage="For educational and legitimate security testing purposes only" 