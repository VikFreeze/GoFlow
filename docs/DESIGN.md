# GoFlow — Design & Plan

A small, self-contained reverse proxy written in Go, from scratch. It is the
capstone for the Boot.dev Backend Developer Path (Python & Go).

This file is the *plan* that the implementation follows. The final, polished
write-up of the decisions lives in `docs/ARCHITECTURE.md`.

## 1. Purpose

Route incoming HTTP/HTTPS traffic to local backends by **hostname** (the
`Host` header for plaintext HTTP, the SNI name for TLS), with:

- multiple hostnames per route (aliases)
- per-route source-IP allowlist (CIDR) for LAN-only routes
- transparent WebSocket upgrade
- HTTP -> HTTPS redirect
- TLS via per-route PEM files, and ACME/Let's Encrypt (lego, HTTP-01)
- a minimal embedded web management UI (single admin, password from env)
- route persistence on disk, surviving restarts
- graceful shutdown, structured logging, `/healthz`

It replaces a Zoraxy deployment (AGPL). Zoraxy is the *reference for the
config model only* — no Zoraxy code is copied (license), and no code is carried
over from the discarded earlier GoFlow attempt (it drifted into a job queue +
Vue UI).

## 2. Why a reverse proxy in Go (and why "from scratch")

- One static binary, trivially containerised, near-zero runtime cost.
- `net/http` gives a real HTTP/1.1 + TLS server, `httputil.ReverseProxy` gives
  correct proxy semantics (including WebSocket 101 piping) for free.
- "From scratch" means: no web framework, no ORM, no DB server. The proxy
  logic, routing, persistence, auth, and UI are all written explicitly so the
  capstone demonstrates the underlying mechanics.

## 3. Key design decisions

### 3.1 Routing model
- A **route** = `{ hosts: [primary, alias, ...], backend: host:port,
  allowlist: [CIDR...], tls: {...}, redirect: bool }`.
- Matching is by **exact hostname** (lowercased, port stripped). Aliases are
  just extra entries in `hosts`. Exact match is chosen over wildcard/CNAME
  because the real-world config is a flat list of subdomains; wildcards add
  a whole matching class for no current need (see Future work).
- One in-memory map `hostname -> *Route`, rebuilt on load and on every edit.
  Lookups are O(1). The map is behind a `sync.RWMutex`.

### 3.2 Persistence choice — JSON file (not SQLite)
- The state is a *list of routes* — a single small document. A JSON file is the
  simplest correct representation: human-readable, diffable, no extra binary,
  no schema migrations, trivially backed up.
- Atomic writes (write temp file in the same dir, then `os.Rename`) mean a
  crash mid-write never leaves a corrupt config.
- SQLite would only pay off with concurrent writers or queryable history. A
  reverse proxy has one writer (the admin) and no queries. JSON + atomic rename
  is the simpler, fully defensible choice.

### 3.3 Hot reload
- The in-memory route map is the source of truth at runtime. Edits go through
  the admin API, which updates the map **and** rewrites the JSON file.
- On startup the file is loaded into the map. A `/api/reload` endpoint (and the
  UI button) re-reads the file into the map — so an external edit to the file
  is picked up without a process restart.
- No file-watcher daemon: an explicit reload is simpler and predictable.

### 3.4 TLS / ACME
- Each TLS route points at `certFile`/`keyFile` (PEM). The HTTPS listener uses
  a `GetCertificate` callback that selects by SNI, so multiple routes each
  serve their own certificate on one :443-equivalent listener.
- If a TLS route has no cert yet, a **self-signed** cert is generated on first
  use (so `curl -k` works in dev) and a warning is logged.
- ACME: `github.com/go-acme/lego` with the **HTTP-01** challenge. On start,
  for each route with `acme: true`, lego registers, solves the challenge
  (served by the proxy on `/.well-known/acme-challenge/<token>`), writes the
  cert/key into the route's cert paths, and loads them into the SNI map.
  A background loop renews when a cert is within 30 days of expiry.
- ACME is **implemented but not exercised live** (no public domain exists); it
  is covered by unit tests (fakes) and a documented manual procedure.

### 3.5 Auth / admin UI
- Single admin. Password is supplied via the `GOFLOW_ADMIN_PASSWORD` env var at
  startup, **bcrypt-hashed**, and the hash is kept in memory only (optionally
  cached to `admin.hash` in the config dir — never in the repo, never
  plaintext). If the env var is unset at first start, a one-time setup flow
  writes the hash and prompts on the next start.
- Sessions: a random token in a `HttpOnly; SameSite=Lax` cookie, mapped in an
  in-memory store with a TTL. No framework, no DB.
- UI: server-rendered `html/template` + vanilla `fetch` for the CRUD/log
  actions. No JS framework, no build step.

### 3.6 Concurrency
- Route map: `sync.RWMutex` (many readers, rare writers).
- Request log: a bounded ring buffer (fixed slice + index, `sync.Mutex`) so the
  live log view has O(1) append and a fixed memory ceiling.
- Each proxy connection is handled by the `http.Server` goroutine model; the
  reverse proxy pipes WebSocket upgrades over the hijacked connection.
- Graceful shutdown: `signal.NotifyContext(SIGINT, SIGTERM)`, then
  `http.Server.Shutdown` with a deadline so in-flight requests finish.

## 4. Out of scope (v1)
Load balancing, GeoIP/country blocking, captcha, plugin system, metrics
dashboards, Kubernetes. See "Future work" in the README.

## 5. Package layout (planned)

```
cmd/goflow/          main: flags, wiring, listeners, graceful shutdown
internal/config/     Route/Config types, JSON persistence, validation
internal/proxy/      matching, allowlist, redirect, ReverseProxy, WS, log buffer
internal/tls/        SNI cert map, PEM load, self-signed fallback
internal/acme/       lego HTTP-01 client wrapper, renewal loop
internal/admin/      auth (bcrypt, sessions), server-rendered UI, JSON API
docs/                ARCHITECTURE.md, DESIGN.md
```

## 6. Acceptance (must be true, verified with real output)
- `go build ./...`, `go vet ./...`, `gofmt -l .` clean, `go test ./...` green.
- Live e2e on the box with throwaway backends on free 18xxx ports: correct
  backend per Host, alias resolves to the same backend, blocked source -> 403,
  WebSocket round-trip, HTTPS with self-signed (`curl -k`), unknown host -> 404.
- UI: unauthenticated -> 401; login with env password works; add route via UI;
  restart; route persists; live log shows the requests.
- Docker build + run serves the UI and proxies a test backend.
- Pushed to GitHub; remote `main` verified with `git ls-remote`.
- No secrets in the repo (`git grep` reviewed).
