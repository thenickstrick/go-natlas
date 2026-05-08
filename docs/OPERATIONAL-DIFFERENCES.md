# Operational differences: Python natlas → go-natlas

A quick reference for operators carrying expectations from Python natlas
into the Go rewrite. For deployment instructions see [DEPLOY.md](DEPLOY.md);
for cutover instructions see [MIGRATION-FROM-PY.md](MIGRATION-FROM-PY.md).

## Stack changes

| Concern              | Python natlas                          | go-natlas                                              |
|----------------------|----------------------------------------|--------------------------------------------------------|
| Language             | Python 3.12 (Flask + SQLAlchemy)       | Go 1.26.3                                              |
| Search/index         | Elasticsearch 7.17                     | OpenSearch 3.6                                         |
| Object store         | MinIO                                  | Garage v1 (any S3-compatible still works)              |
| Tracing UI           | Zipkin (via OTel Collector)            | Jaeger v2 (OTLP-native; Collector forwards to it)      |
| Frontend assets      | Webpack/yarn build pipeline            | Embedded static files; no Node toolchain in the image  |
| Templates            | Jinja2                                 | Go `html/template` + HTMX                              |
| Migrations           | Alembic / Flask-Migrate                | golang-migrate, embedded SQL                           |
| ORM                  | SQLAlchemy                             | sqlc-generated typed queries over pgx / database/sql   |
| Web framework        | Flask 2.x                              | chi + scs sessions + gorilla/csrf                      |
| Sessions             | Flask sessions                         | scs (in-memory today; PG/SQLite store is a swap)       |
| Agent runtime        | Python threads + requests              | Goroutine pool + `net/http` with backoff              |
| Screenshots          | aquatone + xvfb + vncsnapshot          | chromedp (web) — VNC deferred to a follow-up           |
| nmap output parsing  | `natlas-libnmap` fork                  | stdlib `encoding/xml` over the nmap-dtd subset we use  |

## Deployment shape

- **Three binaries, three Docker images.** `natlas-server` (distroless
  static), `natlas-agent` (debian-slim + nmap + Chromium), `natlas-admin`
  (run on demand). No virtualenvs, no Gunicorn, no Webpack dev server.
- **Static config** entirely from environment variables (same model as
  Python natlas; some names changed — see DEPLOY.md for the full list).
- **First-launch admin** is created from the login page when the `users`
  table is empty (or via `natlas-admin user create`). There's no seeded
  default admin password.

## Wire protocol (server ↔ agent)

The agent protocol is a **clean break**. Python and Go agents are not wire
compatible.

- Endpoints moved under `/api/v1/`: `GET /api/v1/work`, `POST
  /api/v1/results`, `POST /api/v1/screenshots/{scan_id}` (multipart, new),
  `GET /api/v1/services`.
- Bearer auth uses `Authorization: Bearer <agent_id>.<token>` (dot
  separator, was colon).
- Agent tokens are **bcrypt-hashed at rest** (was plaintext). The
  `migrate-from-py` tool hashes existing plaintext tokens during cutover so
  Python-era agents keep working without redeploy.
- Screenshots upload as a separate multipart request (was base64 inline in
  the result JSON). Server stores by SHA-256, dedups identical bytes.
- The result JSON's `elapsed` field is now `elapsed_s` everywhere (the
  migrator renames in flight).

## Data store deltas

- **PostgreSQL schema is regenerated** with snake_case naming throughout
  (Python had a mix of `creation_date`, `versionDetection`, etc.).
  Migrations are managed by `golang-migrate` against embedded `.sql` files.
  SQLite is supported as a single-node fallback.
- **OpenSearch index mapping** is structurally identical to the Python ES
  mapping plus an `@timestamp` alias on `ctime` and an `agent_id` keyword
  alongside `agent`. Index names (`nmap`, `nmap_history`) are unchanged.
- **Object store keys** are `screenshots/<sha256>.png`. Content-addressed
  storage gives you free dedup across hosts and across scan retries.
- **Scope storage** uses Postgres native `inet`/`cidr` (was bytea). The
  in-memory scope manager uses `net/netip`.

## Behavioral deltas worth knowing

- **Scope hot-reload**: changes via the web `/admin/scope` page take effect
  on the very next `/api/v1/work` call (the in-memory `ScopeManager`
  reloads from DB on every mutation). Changes via `natlas-admin scope`
  write the row but **do not** signal the running server — plan a rolling
  restart for batch CLI imports.
- **Rescan reaper**: a background goroutine on the server requeues
  rescan_tasks that have been dispatched longer than 10 minutes without
  reporting back. Runs once a minute; cutoff is configurable.
- **Cycle PRNG**: target ordering uses a cycle-walking Feistel network
  keyed by `SCAN_SEED_HEX` (random per startup by default). Set the env
  var to a stable hex value for reproducible scan ordering.
- **CSRF + sessions**: every state-changing web request needs the
  `gorilla.csrf.Token` form field. Behind plain HTTP, the server installs a
  shim so the standard `Origin/Referer` checks still work without HTTPS.
- **First-launch admin path** is the only way to create the first user
  without the CLI; once any user exists, `POST /auth/bootstrap` returns 409
  forever.

## Observability

- All instrumentation goes through OTel. The included compose stack runs
  Jaeger v2 directly behind the OTel Collector — open
  <http://localhost:16686> in dev. Replace Jaeger with whatever sink your
  Collector pipeline forwards to in production (Tempo, Honeycomb, etc.).
- Spans cover: every inbound HTTP handler (otelhttp), every Postgres query
  (otelpgx), every OpenSearch HTTP call (otelhttp transport), every nmap
  invocation, every chromedp capture, the worker dispatch unit, and the
  rescan reaper sweep.
- Metrics emitted: `natlas_scans_total{status}`,
  `natlas_scan_duration_seconds{status}`, `natlas_dispatches_total{reason}`,
  `natlas_screenshots_total{service}`. Counters are cumulative;
  histograms use the OTel default bucket layout.
- Logs are `slog`-emitted with `trace_id`/`span_id` attached when a span
  is on the request context, so log lines correlate cleanly with traces.

## Features deferred from the rewrite (as of Phase 11)

These were called out in the plan as "later" and are not present in the
current deployment:

- **VNC screenshots** — the orchestrator dispatches VNC ports if a VNC
  capturer is registered, but the pure-Go RFB transport itself is a
  follow-up.
- **User invite + password reset email flow** — the `user_invitations`
  table exists, but the SMTP-driven invite-and-reset round trip isn't
  wired into the web UI yet.
- **Scope tags** — the table + JOIN exist; admin write helpers + the UI
  for assigning tags haven't landed.
- **Agent management web pages** — provisioning is CLI-only today; users
  can't rotate their own agent tokens from the web UI.
- **Search page polish** — `/browse?q=...` accepts the OpenSearch
  `query_string` syntax raw; the Python version had a friendlier query
  builder that hasn't been ported.
- **Persistent session store** — sessions live in the server's process
  memory and die on restart; switching to a PG/SQLite store is a one-line
  change in `internal/server/sessions/sessions.go`.
- **Prometheus scrape endpoint** — metrics export over OTLP only;
  Prometheus consumers go through the OTel Collector.
