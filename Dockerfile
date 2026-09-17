FROM golang:1.24.2-alpine@sha256:7772cb5322baa875edd74705556d08f0eeca7b9c4b5367754ce3f2f00041ccee AS builder

WORKDIR /app

ARG VERSION=0.7.0

# Copy module files first and download deps to leverage Docker layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY main.go ./
COPY internal/ ./internal/

# Build the binary with optimizations
RUN CGO_ENABLED=0 GOOS=linux go build -o subenum -ldflags="-w -s -X main.Version=${VERSION}" .

FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3

WORKDIR /home/nonroot

COPY --from=builder /app/subenum /usr/local/bin/subenum
COPY examples/ ./examples/

VOLUME ["/data"]

USER nonroot

ENTRYPOINT ["/usr/local/bin/subenum"]

CMD ["-version"]

LABEL org.opencontainers.image.title="subenum"
LABEL org.opencontainers.image.description="A Go-based CLI tool for subdomain enumeration"
LABEL org.opencontainers.image.source="https://github.com/TMHSDigital/subenum"
LABEL org.opencontainers.image.licenses="GPL-3.0"
LABEL org.opencontainers.image.documentation="https://github.com/TMHSDigital/subenum/blob/main/README.md"
LABEL org.opencontainers.image.vendor="Educational Use Only"
LABEL org.opencontainers.image.usage="For educational and legitimate security testing purposes only"
