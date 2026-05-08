# Deploying go-natlas

This guide walks an operator through standing up a fresh natlas deployment.
For migrating from the Python implementation, see
[MIGRATION-FROM-PY.md](MIGRATION-FROM-PY.md).

## Components

A complete natlas deployment is three binaries plus four backing services:

| Component         | What it is                                | Where it lives           |
|-------------------|-------------------------------------------|--------------------------|
| `natlas-server`   | HTTP control plane + web UI               | one process per cluster  |
| `natlas-agent`    | Polls server, runs nmap, captures shots   | one or more workers      |
| `natlas-admin`    | Operator CLI (users, agents, scope, etc)  | run on demand            |
| PostgreSQL 17     | Relational store                          | required (or SQLite)     |
| SQLite            | Single-node fallback for the DB           | required (or PostgreSQL) |
| OpenSearch 3.6    | Scan results + history index              | required                 |
| Garage v1 (or any S3-compatible) | Screenshot blob store      | required for screenshots |
| OTel Collector + Jaeger v2 | Distributed tracing UI           | optional                 |
| SMTP (e.g. MailDev in dev) | Password-reset / invite email    | optional                 |

The dev `docker-compose.yml` under `deploy/` brings up every service on a
single host with Postgres 17.2, OpenSearch 3.6.0, Garage v1.0.1, Jaeger
v2.3.0, OTel Collector 0.112.0, MailDev, plus the server and agent built
from source. Use it as a starting reference, **not** as a production
configuration — credentials are baked in.

## Quick start (development)

Build the operator CLI once, then drive everything through `natlas`:

```bash
make build              # writes ./bin/natlas (+ natlas-server / -agent / -admin)
./bin/natlas up         # build images + start the dev stack
./bin/natlas logs       # tail all services (./bin/natlas logs server for one)
./bin/natlas ps         # container state
./bin/natlas rebuild    # rebuild + recreate server + agent (the inner-loop verb)
./bin/natlas restart server  # restart only, no rebuild
./bin/natlas down       # stop, volumes preserved
./bin/natlas nuke       # stop + delete every named volume
```

The inner-loop edit→run cycle:

```bash
# you change Go code
./bin/natlas rebuild server   # rebuilds the server image + recreates the container
./bin/natlas logs server      # watch the new version come up
```

`natlas rebuild` differs from `natlas restart` (which is a no-rebuild bounce)
and from `natlas build` (which produces a new image but doesn't swap the
running container).

Symlink it onto your `PATH` for the canonical UX:

```bash
ln -s "$(pwd)/bin/natlas" /usr/local/bin/natlas
natlas up
```

The Makefile keeps `make up` / `make down` / `make logs` / `make ps` / `make nuke`
as aliases for operators who'd rather not build a binary first; both paths
are equivalent.

Wait for the OpenSearch container to settle (it takes ~20s on first start),
then point a browser at <http://localhost:5001/>. The login page will detect
that no users exist and offer a one-shot first-launch admin creation form.

The bundled compose intentionally sets `AGENT_AUTH_REQUIRED=false` on the
server so the bundled agent connects without an operator first running
`natlas-admin agent create`. **Production deployments must leave that
default in place** (it defaults to `true`) and provision agents via the
CLI — see *Bootstrapping an agent* below.

After the first user lands you can:

- Add scope rows from `/admin/scope` (the in-memory dispatcher hot-reloads).
  Try `127.0.0.1/32` for a no-network-touch demo; the agent scans loopback
  once per cycle.
- Watch the agent's logs (`make logs`) pick up work within a poll cycle.
- Visit Jaeger at <http://localhost:16686/> and pick `natlas-server` or
  `natlas-agent` to see the per-scan trace.

## Running natlas-admin against the dev stack

`natlas admin <args>` proxies into the in-cluster `natlas-admin` binary
that ships in the server image. No local Go toolchain or published Postgres
port required:

```bash
natlas admin user list
natlas admin user create --admin admin@example.com
natlas admin agent create --name primary admin@example.com
natlas admin scope add 10.0.0.0/24
natlas admin scope blacklist 10.0.0.5/32
natlas admin services upload ./services.txt
```

The container already has `POSTGRES_URL` set so admin commands target the
same database the server is using. For ad-hoc CLI use against a different
database (e.g. running `migrate-from-py` against an external Python natlas
deployment), build locally with `make build` and run `./bin/natlas-admin`
directly with `POSTGRES_URL` (or `SQLITE_PATH`) in your shell.

There's also a convenience `natlas psql` that drops you into an interactive
psql shell against the dev DB.

## Building from source

The repo expects Go 1.26.3.

```bash
make build           # writes ./bin/natlas-server, ./bin/natlas-agent, ./bin/natlas-admin
make test            # go test ./...
make test-integration # go test -tags=integration ./... (needs Docker for testcontainers)
```

The Dockerfiles under `deploy/` produce a distroless `natlas-server` image
and a debian-slim `natlas-agent` image (slim because the agent needs nmap +
Chromium for screenshots; the server is a static binary).

## Configuration

natlas is entirely env-driven. Every setting reads through
`envconfig`-tagged structs in `internal/config/config.go`; defaults below
match what's in code today.

### `natlas-server`

| Variable                       | Default                                | Notes |
|--------------------------------|----------------------------------------|-------|
| `HTTP_ADDR`                    | `:5001`                                | listen address |
| `PUBLIC_URL`                   | `http://localhost:5001`                | drives the `Secure` cookie attr + the CSRF plaintext-mode hook; set to your `https://...` URL in prod |
| `SECRET_KEY`                   | (required)                             | first 32 bytes feed gorilla/csrf and the session manager — use a long, randomly generated value |
| `LOG_LEVEL`                    | `info`                                 | `debug` / `info` / `warn` / `error` |
| `LOG_FORMAT`                   | `json`                                 | `json` or `text` |
| `POSTGRES_URL`                 | (required if no SQLite)                | e.g. `postgres://natlas:pw@host/natlas?sslmode=disable` |
| `SQLITE_PATH`                  | (required if no Postgres)              | mutually exclusive with `POSTGRES_URL`; single-node fallback |
| `OPENSEARCH_URL`               | `http://opensearch:9200`               | |
| `OPENSEARCH_USERNAME`          | `admin`                                | |
| `OPENSEARCH_PASSWORD`          | (required)                             | |
| `OPENSEARCH_INSECURE_TLS`      | `false`                                | skip cert verification (dev) |
| `S3_ENDPOINT`                  | `garage:3900`                          | any S3-compatible host:port |
| `S3_BUCKET`                    | `natlas-screenshots`                   | must already exist |
| `S3_ACCESS_KEY`                | (required)                             | |
| `S3_SECRET_KEY`                | (required)                             | |
| `S3_REGION`                    | `garage`                               | required for AWS S3, arbitrary for Garage |
| `S3_USE_TLS`                   | `false`                                | |
| `SMTP_HOST` / `SMTP_PORT`      | (unset) / `587`                        | optional; used for password-reset + invite email |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | (unset) / (unset)                   | basic auth |
| `SMTP_FROM`                    | `noreply@natlas.local`                 | |
| `SMTP_USE_TLS`                 | `true`                                 | |
| `OTEL_ENABLED`                 | `true`                                 | turn off entirely if you don't want OTel exports |
| `OTEL_EXPORTER_OTLP_ENDPOINT`  | `otel:4317`                            | OTLP/gRPC target |
| `OTEL_EXPORTER_OTLP_INSECURE`  | `true`                                 | gRPC plaintext |
| `SCAN_SEED_HEX`                | (random per startup)                   | hex-encoded seed for the cycle-walking PRP; set to a stable value to make scan ordering reproducible across restarts |
| `AGENT_AUTH_REQUIRED`          | `true`                                 | gates the `/api/v1/*` bearer-auth middleware; **only** set false in trusted dev networks |

### `natlas-agent`

| Variable                          | Default                  | Notes |
|-----------------------------------|--------------------------|-------|
| `NATLAS_SERVER_URL`               | `http://server:5001`     | scheme + host + port of the server |
| `NATLAS_AGENT_ID` / `NATLAS_AGENT_TOKEN` | (unset)           | bearer credentials minted by `natlas-admin agent create` |
| `NATLAS_MAX_WORKERS`              | `3`                      | concurrent scans |
| `NATLAS_POLL_INTERVAL`            | `10s`                    | (currently informational; the worker pool is semaphore-driven) |
| `NATLAS_REQUEST_TIMEOUT`          | `15s`                    | per-attempt HTTP timeout |
| `NATLAS_DATA_DIR`                 | `/data`                  | scratch tempdir parent |
| `NATLAS_WEB_SCREENSHOTS`          | `true`                   | toggles the chromedp transport |
| `NATLAS_WEB_SCREENSHOT_TIMEOUT`   | `60s`                    | per-capture deadline |
| `CHROMEDP_PATH`                   | (auto)                   | absolute path to a Chromium binary; chromedp auto-discovers when empty |
| `OTEL_*`                          | (same as server)         | |
| `LOG_LEVEL` / `LOG_FORMAT`        | `info` / `json`          | |

### `natlas-admin`

The CLI only needs the DB; it never touches OpenSearch, the object store, or
sessions. Set either `POSTGRES_URL` **or** `SQLITE_PATH` (mutually
exclusive) plus optionally `LOG_LEVEL` / `LOG_FORMAT`. Default log format is
`text` because admins read it interactively.

## First-launch admin

There is no out-of-band seed file. The first time anyone visits
`/auth/login` against an empty `users` table, the page renders a
"Create the initial admin" form instead. Submitting it provisions the user
and logs them in. Subsequent visits to that endpoint after any user exists
return 409 — the path can't be used to add rogue admins later.

If you'd rather not rely on a browser for the initial setup, use the CLI:

```bash
natlas-admin user create --admin admin@example.com
# prompts for password (twice, no echo)
```

## Bootstrapping an agent

```bash
natlas-admin agent create --name primary admin@example.com
```

prints credentials **once**:

```
Agent credentials minted. Save them NOW; the token cannot be retrieved later.
------------------------------------------------------------
  Agent DB ID : 1
  Agent ID    : 4e021ef0098ef350
  Token       : yoiwljno7apujgcwowlqznle2vzn24vlvwn25gi
  Bearer      : 4e021ef0098ef350.yoiwljno7apujgcwowlqznle2vzn24vlvwn25gi
------------------------------------------------------------
Configure the agent with:
  NATLAS_AGENT_ID=4e021ef0098ef350
  NATLAS_AGENT_TOKEN=yoiwljno7apujgcwowlqznle2vzn24vlvwn25gi
```

The token is bcrypt-hashed at rest; **the plaintext is never recoverable**.
If an agent loses its token, rotate with `natlas-admin agent rotate-token
<agent_id>` (mints a fresh token + invalidates the old one).

## Scope management

Scope changes have two paths with different semantics:

- **Web UI** (`/admin/scope` for admins): writes the row **and** hot-reloads
  the in-memory dispatcher. The next `/api/v1/work` call sees the change.
- **CLI** (`natlas-admin scope add|blacklist|remove|import|export`): writes
  the row but does **not** signal the running server. Operators using the
  CLI for batch imports should plan for a rolling restart so the scope
  manager picks up the new state.

Either path normalizes CIDRs through `Masked()` and recomputes start/stop
addresses; you can re-import an existing prefix idempotently.

## Health endpoints

| Endpoint                     | Purpose                            |
|------------------------------|------------------------------------|
| `GET /healthz`               | static liveness — returns 200 if the process is running |
| `GET /readyz`                | pings the configured DB; 503 if the ping fails |
| `GET /static/*`              | embedded CSS + HTMX assets         |

Wire `/healthz` to the kubelet livenessProbe and `/readyz` to the
readinessProbe.

## TLS + production hardening

The server doesn't terminate TLS itself — front it with a reverse proxy
(nginx / Caddy / Traefik / a cloud load balancer) and set `PUBLIC_URL` to
the **external** `https://` URL. Two things hinge on that:

- `PUBLIC_URL` starting with `https://` flips the session cookie + CSRF
  cookie to `Secure`.
- The CSRF middleware enables strict origin checks under HTTPS; under
  plain HTTP it relies on a `PlaintextHTTPRequest` shim instead.

Rotate `SECRET_KEY` at deploy time and never commit it. The signing key
backs both the session store and the CSRF token; rotating it logs every
existing session out, which is usually fine on a maintenance window.

Set `AGENT_AUTH_REQUIRED=true` (the default) in production. The compose
default is `false` only because the dev workflow standalone agent has no
DB-registered identity yet.

## Backups

Two systems hold persistent state:

- **PostgreSQL** — the source of truth for users/agents/scope/rescans/etc.
  Standard `pg_dump`/streaming-replication strategies apply.
- **OpenSearch** — scan results. Snapshots via the `_snapshot` API to S3
  are the canonical path; configure a snapshot repository pointing at
  Garage or your prod S3 bucket.

Object store contents (screenshots) are content-addressed by SHA-256 and
re-uploaded on subsequent scans, so losing them only loses *historical*
imagery — current scans replenish on the next cycle.

## Observability

When OTel is on, every server-side HTTP handler, every PG query (via
otelpgx), every OpenSearch call, every nmap subprocess, every chromedp
capture, every rescan-reaper sweep, and every agent dispatch produces a
span. The agent's outbound HTTP also traces. With the dev compose stack:

- Jaeger UI: <http://localhost:16686/>
- OTel Collector OTLP: `localhost:4317` (gRPC) / `localhost:4318` (HTTP)
- Optional MailDev UI: <http://localhost:1080/>

Metrics emitted by the server + agent (counter / histogram, labels):

- `natlas_scans_total{status}` — `ok|failed|timed_out|submit_failed|cancelled`
- `natlas_scan_duration_seconds{status}`
- `natlas_dispatches_total{reason}` — `automatic|requested|manual`
- `natlas_screenshots_total{service}` — `HTTP|HTTPS|VNC`

Both server and agent honor the standard `OTEL_*` env vars listed above;
configure your OTel Collector to forward to Prometheus, Tempo, Honeycomb,
or whatever your environment uses.
