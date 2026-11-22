# GoFlow — Architecture

This document explains *how* GoFlow is built and *why*. `DESIGN.md` is the
original plan; this is the final write-up of the decisions, including the
"pick the simpler defensible option" trade-offs the project agreed to make
explicit.

## 1. Design goals

GoFlow is a single static binary, written in plain Go standard library plus
two third-party dependencies ([lego](https://github.com/go-acme/lego) for ACME
and `x/crypto` for bcrypt). The goals, in priority order:

1. **Small and auditable** — one process, a handful of packages, no framework.
2. **Boring and correct** — the standard library `httputil.ReverseProxy` does
   the heavy lifting; GoFlow adds routing policy, TLS selection, and
   management around it.
3. **Self-contained** — config, TLS state, ACME state, and the admin hash all
   live in one `--config-dir` volume. No database, no external services.

## 2. Package layout and responsibilities

```
cmd/goflow        Wires everything together. Owns the listeners, the cert
                  store, and graceful shutdown. Knows about every package;
                  no other package imports it.
internal/proxy    Pure request pipeline: host matching, allowlist check,
                  redirect, reverse proxy, request logging. No I/O beyond the
                  HTTP layer; no knowledge of config files or TLS.
internal/config   Data types + validation + atomic persistence. Pure data.
internal/tls      SNI-based certificate store: loads PEM files, picks a cert
                  per SNI, self-signed fallback, expiry queries.
internal/acme     lego-based HTTP-01 issuer. Writes PEM files into the config
                  dir and feeds them to the tls store; runs a renewal loop.
internal/admin    HTTP handlers for the web UI and JSON API. Depends on
                  config (to read/write routes) and nothing else heavy.
```

Dependency direction is strictly `cmd → {proxy, config, tls, acme, admin}` and
`admin → config`. Nothing in `internal/` imports `cmd/`. This keeps the proxy
core testable without any filesystem or network state.

## 3. Request pipeline

```
listener ──► healthz mux ──► /admin mux ──► proxy.Handler
                                        │
                          1. matcher: route by Host header (or SNI)
                          2. no route           → 404
                          3. allowlist mismatch → 403
                          4. redirectHttp && HTTP → 301 https://…
                          5. reverseProxy(route) serves the request
                          6. ring log records the entry
```

### 3.1 Host matching

Routes are matched on the `Host` header with the port stripped. For TLS the
same hostname is available as SNI, which the cert store uses independently —
routing and TLS selection are decoupled and both key off the hostname.
Matching is a linear scan; at the scale this proxy targets (a dozen routes)
that is simpler and faster to reason about than a trie or hash index.

### 3.2 WebSocket upgrades

`httputil.ReverseProxy` passes `Connection: Upgrade` / `Upgrade` headers
through and hijacks the connection when the backend replies `101`, so
Websockets work with no special code in the proxy path.

One subtlety: on a `101` response the standard library server writes the
status line directly to the connection and **bypasses** `ResponseWriter.WriteHeader`,
so a wrapper that records the status never sees the `101`. GoFlow therefore
detects upgrades from the *request* headers (`Upgrade: websocket`) and logs
completed upgrades as `status=101, websocket=true`. This is asserted by
`TestWebSocketUpgradeIsLogged`.

### 3.3 Request log

A fixed-size ring buffer (1024 entries) protected by a mutex. Each entry:
time, client IP, host, method, path, route name, status, WebSocket flag,
duration, and an error if the proxy failed. The admin UI polls it via
`/admin/api/logs`. A ring buffer was chosen over an append file or database
because it needs zero maintenance, cannot grow without bound, and the request
log is a diagnostic, not a record — losing the oldest entries is fine.

## 4. Configuration

### 4.1 Format and persistence

Routes live in `routes.json` as plain JSON (not YAML — it's the format the
admin UI writes, and JSON is what the language's own encoder emits). `Save`
writes atomically: write to a temp file in the same directory, then rename
over the target, so a crash mid-write can never leave a truncated
`routes.json` behind.

### 4.2 Relative paths anchor at the config dir (a real bug, fixed)

`tlsCertFile` / `tlsKeyFile` may be relative. Originally validation `stat`-ed
those paths against the process CWD, while the TLS store resolved them
against the config dir — a mismatch that worked for a developer running from
the repo root and would have silently broken in the container (CWD `/`,
config dir `/config`). The fix: `Load` anchors every relative cert path at the
config file's directory, and `Route.ValidateCertFiles(baseDir)` takes the
explicit base. `TestCertPathsResolveRelativeToConfigFileDir` locks this in.

### 4.3 Hot reload

The admin UI's *Reload* re-runs `Load` + validation and swaps the matcher's
route table atomically (the matcher copies the slice under a read lock, so
in-flight requests keep the old table). No restart needed.

## 5. TLS

- One `tls.Certificate` per route, loaded from PEM files; selected per
  connection by SNI (`GetCertificate`), with the first-loaded cert as
  fallback.
- Routes with neither PEM files nor ACME get a generated self-signed cert so
  the HTTPS listener always has material for every configured host.
- `MinVersion: TLS 1.2`.
- `Expiry` is used by the ACME loop to decide renewal (due at 30 days).

## 6. ACME

`internal/acme` wraps lego with a single HTTP-01 provider. Design points:

- **Challenge store**: in-memory map of `token → token` with a 10-minute TTL
  and lazy eviction; the HTTP listener serves it at `/.well-known/acme-challenge/…`
  only for tokens that exist. A route without a live challenge gets a 404,
  never a guess.
- **Account**: key persisted to `acme-account.json`; certs to
  `acme-certs/<name>.crt|.key`, then handed to the tls store.
- **Renewal**: a single hourly ticker walks all `acme: true` routes, and
  renews those whose cert is within 30 days of expiry. One loop, no
  per-route goroutines.

Implemented and unit-tested (challenge store, expiry math, renewal
scheduling), but deliberately **not** exercised against Let's Encrypt — there
is no public domain, and the test suite must not depend on an external
authority.

## 7. Admin UI

Server-rendered `html/template` pages plus a small JSON API (`/api/login`,
`/api/routes`, `/api/logs`, `/api/reload`). No JS framework, no build step —
a few `fetch` calls in the templates. The rationale for picking the simpler
option over a SPA: the UI has four screens and one user; a build step would
add a node toolchain, an asset pipeline, and a second attack surface for a
UI whose job is to edit a JSON file.

**Authentication.** One admin user. The password is read from
`GOFLOW_ADMIN_PASSWORD` at startup; if unset, a random password is generated,
**printed once to the log**, and stored as a bcrypt hash in `admin.hash`.
The plain password is never written to disk. Sessions are a signed random
token in an `HttpOnly`, `SameSite=Lax` cookie (12h TTL), checked by a wrapper
that returns `401` on the API and a redirect to `/admin/login` on pages.

**Mounting.** The UI is mounted at the `/admin` prefix with explicit prefix
stripping in the mux, so template links, form actions, and API paths are all
relative to the stripped root. (The first version relied on the mux's
implicit prefix handling and lost `/admin/api/*` to the catch-all — fixed by
owning the prefix in one place.)

## 8. Process lifecycle

- `main` parses flags, builds the app, and runs it in a goroutine-supervised
  `http.Server` pair (HTTP + HTTPS).
- `SIGINT`/`SIGTERM` → `Server.Shutdown` with a deadline, so in-flight
  requests drain before exit.
- `slog` throughout, level selectable via `--log-level`.
- `/healthz` returns `ok` on both listeners — the same mux that serves
  traffic, so a 200 there means the router is up.

## 9. Container

Multi-stage: `golang:1.22` builder (module cache separated from source cache,
`CGO_ENABLED=0`) → `gcr.io/distroless/static:nonroot`. The final image
contains only the binary and an empty `/config` directory. It runs as
`nonroot` (uid 65532). The config dir is a volume; **the host directory must
be owned by uid 65532** (or the app will not be able to write
`routes.json`/`admin.hash` after a hot edit). Compose wires the port, env var,
and volume.

### 9.1 WSL networking caveat (observed during verification)

On the WSL 2 Docker install used for verification (Docker 20.10.11),
`--network host` does **not** expose container ports on the WSL host, and the
container's own netns cannot reach the WSL host's loopback. The verified
pattern is bridge networking with `-p` publishing, and backends bound to the
WSL host's **eth0 LAN IP** (not `127.0.0.1`). This is a property of that
Docker deployment, not of GoFlow — the same image on a normal Linux host can
use host networking or bind to loopback as usual.

## 10. Explicit "simpler option" choices

Per the project rule ("when two designs are both defensible, pick the simpler
one and justify it here"):

| Decision | Alternative considered | Why the simpler one |
| --- | --- | --- |
| JSON `routes.json` | SQLite | A dozen routes; atomic-rename JSON is diffable, greppable, and needs no driver. SQLite's durability buys nothing at this scale. |
| Linear host scan | Hash/trie index | O(n) for n≈10 is nanoseconds; the index adds code and a second source of truth for matching rules. |
| Ring buffer request log | Persistent log / metrics DB | The log is a diagnostic; bounded memory, zero maintenance, nothing to back up. |
| One admin user, cookie session | User table, JWTs | Single-operator tool. A user table and token infra would be security surface without a second user to secure it for. |
| Server-rendered templates | SPA with a JS framework | Four screens, one user. No build step, no asset pipeline, no framework CVEs. |
| Single hourly ACME loop | Per-route watchers | One ticker is easier to reason about and test; 30 routes checked every hour is nothing. |
| HTTP-01 only | HTTP-01 + DNS-01 | No public domain exists for this project; DNS-01 needs provider credentials in the config, which the security rules forbid. |
| Self-signed fallback cert | Refuse to serve host without cert | A host with no material would be a TLS error in the browser; a labeled self-signed cert keeps the proxy usable while you obtain a real cert. |
| In-memory session tokens | Signed/JWT sessions | Tokens are random 32-byte values; the server holds them. Stateful sessions are the smaller, auditable design for one user. |

## 11. Security posture

- No plaintext passwords anywhere: env var or generated-then-hashed.
- No credentials, tokens, or secrets in the repo or CI (CI generates its
  smoke-test password at runtime with `openssl rand`).
- Allowlists deny by construction: a malformed CIDR matches nothing (fail
  closed), and an empty allowlist is the only open mode.
- Admin API is session-gated with `401`; the UI cookie is `HttpOnly` and
  `SameSite=Lax`.
- Container: distroless (no shell, no package manager, minimal CVE surface),
  non-root user.
- The live test suite never talks to production backends; it uses throwaway
  echo backends on free high-numbered ports.

## 12. Test strategy

- `internal/proxy` — table-driven tests of the pure pipeline (host, alias,
  allowlist, redirect, WebSocket handshake, persistence) against
  `httptest` backends.
- `internal/config` — normalisation, validation (incl. CIDR and cert-file
  anchoring), atomic save round-trip.
- `internal/tls` — SNI selection, PEM load, self-signed generation, expiry
  (second-precision tolerance).
- `internal/acme` — challenge store TTL/eviction, expiry, renewal scheduling.
- `internal/admin` — bootstrap, 401 gating, login, route CRUD, log viewer,
  page renders.
- `cmd/goflow` — app-level e2e: routing, unknown host 404, allowlist
  deny/allow, redirect, healthz, HTTPS with a route cert, WebSocket
  round-trip, admin login + hot-add, persistence across restart.

CI (`github/workflows/ci.yml`) runs `gofmt`, `go vet`, `go build`, the full
race-enabled suite, a Docker build, and a container `/healthz` smoke test.
