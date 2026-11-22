# syntax=docker/dockerfile:1

# ---- builder -----------------------------------------------------------
FROM golang:1.22 AS builder

WORKDIR /src

# Cache module downloads separately from source changes.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build \
        -trimpath \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/goflow ./cmd/goflow

# Writable config dir (routes.json, admin.hash, certs, ACME state).
# Built here because the runtime stage (distroless) has no shell.
RUN mkdir -p /out/config

# ---- runtime ------------------------------------------------------------
# distroless/static: no shell, no package manager, tiny attack surface.
# The :nonroot variant runs as uid/gid 65532 by default.
FROM gcr.io/distroless/static-debian12:nonroot

USER nonroot:nonroot
WORKDIR /app

COPY --from=builder /out/goflow /app/goflow
COPY --from=builder --chown=nonroot:nonroot /out/config /config
VOLUME ["/config"]

# HTTP and HTTPS listeners (override with --listen-http / --listen-https).
EXPOSE 8080 8443

# The admin password MUST be supplied at runtime via the
# GOFLOW_ADMIN_PASSWORD environment variable (never baked into the image).
ENV GOFLOW_CONFIG_DIR=/config

ENTRYPOINT ["/app/goflow"]
CMD ["--listen-http", ":8080", "--listen-https", ":8443", "--config-dir", "/config"]
