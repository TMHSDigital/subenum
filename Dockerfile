# Builder uses a current, supported Go toolchain (go.mod 1.26.0 is only the
# minimum); Dependabot keeps both digests fresh. It runs on the build host's
# platform and cross-compiles for the target, so multi-arch images (#40) need
# no QEMU emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS builder

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
# Every top-level .go file: main is split across several (main.go,
# main_summary.go, ...); _test.go files are ignored by go build.
COPY *.go ./
COPY internal/ ./internal/
# The default wordlist is embedded in the binary (#63).
COPY data/subdomains-5k.txt data/data.go ./data/

# Build the binary with optimizations
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -o subenum -ldflags="-w -s -X main.Version=${VERSION}" .

FROM gcr.io/distroless/static:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99

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
