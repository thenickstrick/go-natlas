# go-natlas

A Go rewrite of [natlas](https://github.com/natlas/natlas), the distributed
nmap-based network reconnaissance platform. natlas continuously scans a
configured scope, indexes the results into a search backend, and exposes a
web UI to browse and request rescans.

The Go implementation swaps Elasticsearch for OpenSearch, MinIO for Garage,
the Webpack frontend pipeline for embedded `html/template` + HTMX, and ships
as three statically-linked binaries (`natlas-server`, `natlas-agent`,
`natlas-admin`). It is **not wire-compatible** with the Python natlas
agent — see the docs below for the migration path.

## Components

- `cmd/natlas-server` — HTTP control plane, web UI, agent dispatch, result indexing.
- `cmd/natlas-agent` — polls the server, runs nmap, captures screenshots.
- `cmd/natlas-admin` — operator CLI (users, agents, scope, services, migrate-from-py).

## Documentation

- [docs/DEPLOY.md](docs/DEPLOY.md) — deploying from scratch (env vars, services, first-launch admin, observability).
- [docs/MIGRATION-FROM-PY.md](docs/MIGRATION-FROM-PY.md) — cutover from Python natlas using the `migrate-from-py` tool.
- [docs/OPERATIONAL-DIFFERENCES.md](docs/OPERATIONAL-DIFFERENCES.md) — what changes operationally vs Python natlas (stack swap, wire protocol, deferred features).

## Quick start

```bash
make up        # docker compose up -d --build (Postgres, OpenSearch, Garage, Jaeger, OTel Col, MailDev, server, agent)
make logs      # tail the stack
make down      # stop
```

Then visit <http://localhost:5001/> — the login page renders a one-shot
"create initial admin" form on first launch. Add `127.0.0.1/32` under
**Scope** for a no-network-touch demo, then watch the agent log scans and
the trace appear in Jaeger at <http://localhost:16686/>.

The bundled `natlas-admin` CLI ships in the server image:

```bash
docker compose -f deploy/docker-compose.yml exec server /natlas-admin user list
```

## Development

Requires Go 1.26.2.

```bash
make build              # bin/natlas-server, bin/natlas-agent, bin/natlas-admin
make test               # go test ./...
make test-integration   # go test -tags=integration ./...   (needs Docker)
```
