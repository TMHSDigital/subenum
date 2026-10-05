# Builder uses a current, supported Go toolchain (go.mod 1.24.2 is only the
# minimum); Dependabot keeps both digests fresh. It runs on the build host's
# platform and cross-compiles for the target, so multi-arch images (#40) need
# no QEMU emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS builder

# Set by BuildKit for each platform being built.
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

# Overridden by `make docker-build` and release CI; "dev" for ad-hoc builds.
ARG VERSION=dev

# Copy module files first and download deps to leverage Docker layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY main.go ./
COPY internal/ ./internal/

# Build the binary with optimizations
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -o subenum -ldflags="-w -s -X main.Version=${VERSION}" .

FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3

WORKDIR /home/nonroot

COPY --from=builder /app/subenum /usr/local/bin/subenum
COPY examples/ ./examples/

VOLUME ["/data"]

USER nonroot

ENTRYPOINT ["/usr/local/bin/subenum"]

CMD ["-version"]

LABEL org.opencontainers.image.title="subenum"
LABEL org.opencontainers.image.description="Fast concurrent subdomain enumeration via DNS brute-forcing"
LABEL org.opencontainers.image.source="https://github.com/TMHSDigital/subenum"
LABEL org.opencontainers.image.licenses="GPL-3.0"
LABEL org.opencontainers.image.documentation="https://github.com/TMHSDigital/subenum/blob/main/README.md"
LABEL org.opencontainers.image.vendor="TMHSDigital"
LABEL org.opencontainers.image.usage="For educational and legitimate security testing purposes only"
