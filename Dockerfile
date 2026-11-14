# Builder uses a current, supported Go toolchain (go.mod 1.26.0 is only the
# minimum); Dependabot keeps both digests fresh. It runs on the build host's
# platform and cross-compiles for the target, so multi-arch images (#40) need
# no QEMU emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS builder

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
# subenum mcp runs scans through the public library (#131).
COPY pkg/ ./pkg/
# The default wordlist is embedded in the binary (#63), and so are the lab
# scenarios that subenum mcp's lab_scan serves (#131).
COPY data/subdomains-5k.txt data/data.go ./data/
COPY examples/labs/*.zone examples/labs/words.txt ./examples/labs/

# Build the binary with optimizations
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -o subenum -ldflags="-w -s -X main.Version=${VERSION}" .

FROM gcr.io/distroless/static:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931

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
