# GoFlow

A small, self-contained **reverse proxy** written in Go, built from scratch. It
routes incoming HTTP/HTTPS traffic to local backends by **hostname**, with
aliases, per-route source-IP allowlists, transparent WebSocket upgrades,
HTTP→HTTPS redirects, per-route TLS, optional ACME/Let's Encrypt, and an
embedded single-user web management UI.

GoFlow is the capstone project for the **Boot.dev Backend Developer Path
(Python & Go)**.

```
                      ┌─────────────────────────────────────────┐
  Host: a.example.com │              GoFlow                     │
  ──────────────────► │  host match → route → allowlist check   │──► 10.0.0.5:3000
                      │  (SNI for TLS)   (CIDR)  WebSocket ok   │
  Host: b.example.com │  HTTP→HTTPS redirect · per-route TLS    │──► 127.0.0.1:8081
  ──────────────────► │  /admin  web UI · /healthz              │
                      └─────────────────────────────────────────┘
```

## Features

- **Host-based routing** — match on the `Host` header (HTTP) or SNI (TLS).
- **Aliases** — one route can match many hostnames.
- **Per-route allowlist** — CIDR source-IP filter; unmatched clients get `403`.
- **WebSocket** — `Connection`/`Upgrade` requests are proxied transparently.
- **HTTP → HTTPS** — optional per-route `301` redirect.
- **TLS** — per-route PEM cert/key files, selected by SNI.
- **ACME** — Let's Encrypt (lego, HTTP-01) implemented; see *ACME* below.
- **Web UI** — server-rendered (no JS framework) single-admin UI to manage
  routes and watch the live request log.
- **Persistence** — routes are saved to `routes.json` and survive restarts.
- **Operations** — `slog` structured logs, `/healthz`, graceful shutdown.

## Quickstart

### Build

```sh
go build -o goflow ./cmd/goflow
```

### Run

```sh
export GOFLOW_ADMIN_PASSWORD='pick-a-strong-password'
./goflow \
  --listen-http 127.0.0.1:8080 \
  --listen-https 127.0.0.1:8443 \
  --config-dir ./goflow \
  --log-level info
```

Open `http://127.0.0.1:8080/admin` and log in. Add routes from the UI, or edit
`routes.json` and hit *Reload*.

### Run with Docker

```sh
# Build the image (multi-stage, distroless, non-root)
docker build -t goflow .

# Provide a config dir owned by the container user (uid 65532, "nonroot")
mkdir -p ./goflow
echo '{"routes":[]}' > ./goflow/routes.json
chown -R 65532:65532 ./goflow

export GOFLOW_ADMIN_PASSWORD='pick-a-strong-password'
docker run -d --name goflow \
  -p 8080:8080 -p 8443:8443 \
  -e GOFLOW_ADMIN_PASSWORD \
  -v "$PWD/goflow:/config" \
  goflow
```

Or use the provided `docker-compose.yml` (see it for the volume, env, and port
mappings).

## Configuration

GoFlow reads `routes.json` from `--config-dir` (default `./goflow`). The file is
a JSON document:

```json
{
  "routes": [
    {
      "name": "files",
      "hosts": ["files.dev.test", "shares.dev.test"],
      "backend": "127.0.0.1:41240",
      "allowlist": ["192.168.0.0/16"],
      "redirectHttp": true
    }
  ]
}
```

### Top-level

| Field | Type | Description |
| --- | --- | --- |
| `routes` | array | The list of routes. |

### Route fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | yes | Unique, human-readable identifier used by the UI. |
| `hosts` | []string | yes | Hostnames routed here (optional `:port` suffix). First is the primary, the rest are aliases. |
| `backend` | string | yes | Upstream `host:port` to proxy to. |
| `allowlist` | []string | no | CIDR / IP entries. When set, only matching source IPs are served (else `403`). Empty = open. |
| `tlsCertFile` | string | no | PEM certificate. Relative paths resolve against the config dir. |
| `tlsKeyFile` | string | no | PEM private key. Relative paths resolve against the config dir. |
| `acme` | bool | no | Issue certs via Let's Encrypt (HTTP-01) for this route's hostnames. |
| `redirectHttp` | bool | no | On the HTTP listener, `301` matching hosts to their HTTPS URL. |

A route with **neither** a TLS cert nor `acme` will fall back to an
auto-generated self-signed certificate on the HTTPS listener, so a host always
has *some* TLS material to serve.

## Real-world config

The following table is a representative configuration GoFlow must be able to express (a mix of local backends, one remote backend, an alias pair, and LAN-only routes). These are **example** backends, not proxied to during automated testing (throwaway backends on free high-numbered ports are used instead).

| Hostname | Backend | Notes |
| --- | --- | --- |
| `registry.dev.test` | `localhost:41123` | LAN only |
| `scan.dev.test` | `localhost:41517` | LAN only |
| `chat.dev.test` | `localhost:40392` | |
| `chatbox.dev.test` | `127.0.0.1:41876` | LAN only |
| `vault.dev.test` | `storage.dev.test:41240` | |
| `model.dev.test` | `localhost:40031` | |
| `finder.dev.test` | `localhost:41953` | LAN only |
| `files.dev.test`, `shares.dev.test` | `localhost:41240` | LAN only (alias) |
| `stream.dev.test` | `localhost:40884` | LAN only |

Expressed as GoFlow routes, the "LAN only" rows are simply the same routes with
a LAN CIDR in `allowlist` (e.g. `192.168.0.0/16`), and the `files` / `shares`
row is one route with both hostnames in `hosts`.

## CLI

| Flag | Default | Description |
| --- | --- | --- |
| `--listen-http` | `127.0.0.1:8080` | Plaintext HTTP listener address. |
| `--listen-https` | `127.0.0.1:8443` | TLS listener address. |
| `--config-dir` | `./goflow` | Directory for `routes.json`, `admin.hash`, certs, ACME state. |
| `--log-level` | `info` | `debug`, `info`, `warn`, or `error`. |
| `--version` | — | Print version and exit. |

| Environment | Description |
| --- | --- |
| `GOFLOW_ADMIN_PASSWORD` | Admin password. If unset, a random password is generated and **printed once to the log** at first run, then stored as a bcrypt hash in `admin.hash`. |

## Web UI

Served at `/admin` on the HTTP listener. Single admin user, no JS framework
(server-rendered `html/template` + small fetch/vanilla-JS for the API calls).

- **Login** — session cookie (`HttpOnly`, `SameSite=Lax`, 12h).
- **Routes** — list / add / edit / delete.
- **Logs** — live request log (ring buffer of recent requests).
- **Reload** — re-read `routes.json`.

All `/admin/api/*` endpoints require an authenticated session and return `401`
otherwise.

## ACME (Let's Encrypt)

`acme: true` on a route enables automatic issuance via [lego](https://github.com/go-acme/lego) over the **HTTP-01** challenge. Certs are stored under the config
dir (`acme-certs/`), the account key under `acme-account.json`, and a background
loop checks renewal (due at 30 days) on an hourly interval.

> **Note:** ACME is fully implemented and covered by unit tests (challenge
> store, expiry, renewal scheduling) but is **not exercised in the live test
> suite**, because there is no public domain to point Let's Encrypt at. To use
> it for real: set `acme: true` on a route with a publicly-resolvable hostname,
> make sure the HTTP listener is reachable from the internet on that host, and
> restart. See `docs/ARCHITECTURE.md` for the design.

## Security

- **Admin password** is stored as a **bcrypt hash** in `admin.hash`, never in
  plain text, and never in the repository. It is supplied via
  `GOFLOW_ADMIN_PASSWORD` or generated once at first run.
- **No credentials, tokens, or plaintext passwords** appear anywhere in the
  repo, tests, or CI.
- **Sessions** use an `HttpOnly`, `SameSite=Lax` cookie with a 12-hour TTL.
- **Allowlists** gate "LAN-only" routes by source IP; unmatched clients get
  `403`.
- The **container runs as a non-root user** (`nonroot`, uid 65532) on a
  distroless base.

## Testing

```sh
go test ./...
```

The suite is table-driven where it makes sense and covers the proxy (host /
alias / allowlist / redirect / WebSocket / persistence), config (normalise,
validation, CIDR, atomic save), TLS (SNI, PEM, self-signed, expiry), ACME
(challenge store, renewal), the admin UI (auth, CRUD, logs), and app-level e2e
(routing, hot-add, restart persistence, HTTPS, WebSocket). CI runs `gofmt`,
`go vet`, `go build`, and the race-enabled test suite, plus a Docker build and
a `/healthz` smoke test.

## Project layout

```
cmd/goflow/          # entrypoint, app wiring, listeners, graceful shutdown
internal/proxy/      # host matching, allowlist, redirect, WebSocket, ring log
internal/config/     # route types, validation, atomic JSON persistence
internal/tls/        # SNI cert store, PEM load, self-signed fallback
internal/acme/       # lego HTTP-01 issuer, challenge store, renewal loop
internal/admin/      # web UI, bcrypt auth, sessions, route CRUD, log viewer
docs/                # DESIGN.md (plan), ARCHITECTURE.md (decisions)
Dockerfile           # multi-stage build (golang:1.22 -> distroless nonroot)
docker-compose.yml
.github/workflows/ci.yml
```

See `docs/ARCHITECTURE.md` for the design rationale and the simpler-option
choices that were made.

## Future work

The following are explicitly **out of scope** for v1 and listed here for a
future iteration:

- Load balancing across multiple backends per route
- GeoIP / country blocking
- Captcha
- Plugin system
- Metrics dashboards (e.g. Prometheus)
- Kubernetes / service discovery
