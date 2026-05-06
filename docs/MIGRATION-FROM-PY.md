# Migrating from Python natlas to go-natlas

This guide is for operators who already run a Python natlas deployment
(Flask + Elasticsearch 7.17 + PostgreSQL + MinIO + Webpack) and want to
move to the Go rewrite. For a clean install, see
[DEPLOY.md](DEPLOY.md). For the operational deltas you'll feel after the
cutover, see [OPERATIONAL-DIFFERENCES.md](OPERATIONAL-DIFFERENCES.md).

The migration tooling lives in `natlas-admin migrate-from-py`. It reads from
your Python deployment over its native protocols (libpq + Elasticsearch's
REST API) and writes through the Go destination's standard data layer, so
the new deployment ends up indistinguishable from one that grew up
naturally on Go natlas.

---

## What gets migrated

| Source (Python natlas)             | Destination (Go natlas)               | Notes |
|------------------------------------|---------------------------------------|-------|
| `user`                             | `users`                               | password_hash flows through (both sides bcrypt); column renames are silent |
| `agent`                            | `agents`                              | **plaintext token bcrypt-hashed during migration** so existing deployed agents keep working |
| `scope_item`                       | `scope_items`                         | target string parsed into `netip.Prefix`; start/stop recomputed from the prefix |
| `scopetags` JOIN                   | (read-only)                           | tags are read but **not** written — the destination tag insert helpers aren't on the Store interface yet (deferred follow-up) |
| `rescan_task`                      | `rescan_tasks`                        | `dispatched` bool + `date_dispatched` collapse to `dispatched_at *time.Time`; same for completion |
| `agent_config` (singleton)         | `agent_config`                        | camelCase columns → snake_case; defaults preserved |
| `natlas_services` (singleton)      | `natlas_services`                     | sha256 + blob copied verbatim |
| `scope_log`                        | `scope_log`                           | best-effort; failure non-fatal |
| ES `nmap` (latest)                 | OpenSearch `nmap`                     | doc_id stays the IP; `elapsed` field renames to `elapsed_s` |
| ES `nmap_history`                  | OpenSearch `nmap_history`             | doc_id becomes `scan_id` (deterministic; idempotent reruns) with the source `_id` as fallback |

## What does NOT get migrated

- **Scope tags** (deferred): the JOIN is read but not persisted. Re-tag
  scope rows via the web `/admin/scope` page after migration if needed.
- **User invitations** that were issued but not accepted: the destination
  schema has the table, but the migrator doesn't translate active invites.
  Re-issue them post-cutover.
- **Sessions**: Python natlas used Flask sessions; Go natlas uses scs.
  Every user re-authenticates after the cutover.
- **Anything in the Python project's `data/` runtime tree** (S3 keys,
  manifest files, etc.): screenshots are content-addressed, so the new
  agents will repopulate on the next scan cycle. If you want the existing
  screenshots in the new bucket, copy `screenshots/*.png` between the two
  S3-compatible backends with `mc mirror` or `s3cmd sync` (the keys are
  the SHA-256 hashes — directly portable).

## Pre-flight checklist

Before running the migration:

1. **Snapshot both backends.** A full `pg_dump` of the Python natlas DB
   plus an Elasticsearch `_snapshot` to a known-good repository. Migration
   writes are idempotent against natural keys, so re-running is safe — but
   destructive *re-imports* on the destination still need a way back.

2. **Stand up the destination first** following [DEPLOY.md](DEPLOY.md).
   Confirm the Go server starts, OpenSearch indices exist (`/healthz`
   green, OpenSearch GET `/nmap` and `/nmap_history` return 200), and an
   admin user exists. The migrator writes through `natlas-admin`'s store,
   so the destination DB needs to already be reachable.

3. **Stop the Python agents.** Avoid double-writes during the cutover.
   Leave the Python *server* running so the migrator can read from it.

4. **Confirm versions:**
   - Python natlas: any 0.6.x release exposes the schemas the migrator expects.
   - Source Elasticsearch: 7.17.x.
   - Destination Postgres: 17+ (or SQLite for single-node).
   - Destination OpenSearch: 3.6.x (the bundled mapping is tested against this; 3.x earlier should work).

## Dry run first

Always dry-run before committing. The `--dry-run` flag reads + transforms
both pipelines but writes nothing on either side, so you get the same row
counts and the same per-row errors you'd see in a real run.

```bash
SQLITE_PATH=/var/lib/natlas/natlas.sqlite \
natlas-admin migrate-from-py \
  --src-pg-url 'postgres://natlas:OLD_PW@old-host:5432/natlas?sslmode=disable' \
  --src-es-url 'http://old-es:9200' \
  --src-es-user elastic --src-es-password 'OLD_ES_PW' \
  --dest-os-url 'http://new-opensearch:9200' \
  --dest-os-user admin --dest-os-password 'NEW_OS_PW' \
  --batch-size 1000 \
  --dry-run
```

You'll see a per-pipeline report:

```
Migration report:
  Relational
    users:           42
    agents:          17
    scope_items:     1289
    rescan_tasks:    63
    agent_config:    1
    natlas_services: 1
    scope_log:       284
  Search
    nmap (latest):   3902
    nmap_history:    218443
```

Re-runs after a partial real run are also safe. Relational rows skip on
natural-key conflicts (email, agent_id, `(cidr, blacklist)`); search docs
PUT by deterministic ID so they overwrite cleanly.

## Real run

Drop the `--dry-run`. Plan for the run length: the relational pipeline is
cheap (seconds to a minute), but the search pipeline scrolls + bulk-indexes
every history doc. With the default `--batch-size 500` and a full agent
dispatch every ~5min, plan for roughly one minute per 10k history docs on
modest hardware.

The migrator emits OTel spans for every batch; if your destination
deployment is wired to Jaeger you can watch progress under the
`migrate-from-py` service name.

## Token rotation

**Agent tokens are bcrypt-hashed during migration.** The plaintext from the
old DB is hashed and stored on the new agent row, so existing deployed
Python-era agents authenticate against the new server **without any
redeploy** — same `agent_id` + same plaintext token continues to work,
hashed at rest now instead of bare.

If you'd rather start fresh:

```bash
natlas-admin agent rotate-token <agent_id>   # mints a new token, prints once
```

then redeploy the agent with the new `NATLAS_AGENT_TOKEN`.

## Validation steps

After the run, verify before flipping traffic:

1. **Row counts**:
   ```bash
   psql "$NEW_PG_URL" -c "SELECT count(*) FROM users;"
   psql "$NEW_PG_URL" -c "SELECT count(*) FROM agents;"
   psql "$NEW_PG_URL" -c "SELECT count(*) FROM scope_items;"
   ```
   Compare against the dry-run report.

2. **OpenSearch counts**:
   ```bash
   curl -s -u admin:PW http://new-opensearch:9200/nmap/_count
   curl -s -u admin:PW http://new-opensearch:9200/nmap_history/_count
   ```

3. **Spot-check a host**: load `/host/<known-IP>` on the Go UI. Confirm
   timing, port detail, scripts, and screenshots (if migrated separately
   via `mc mirror`) render. The `nmap_data` blob should be byte-identical
   to the Python view.

4. **Agent connectivity**: pick one stopped Python agent, point it at the
   new server (only env var changes: `NATLAS_SERVER_ADDRESS` →
   `NATLAS_SERVER_URL`), restart, and watch the agent log + Jaeger for a
   `worker.scan` span. Old plaintext token works as-is.

5. **Web rescan**: from the Go UI, request a rescan on a known target.
   The `rescan_task` row should appear, get dispatched on the next agent
   poll, and land back as a "requested" scan.

## Cutover

When validation passes:

1. Stop the Python server.
2. Repoint your reverse proxy / DNS at `natlas-server:5001`.
3. Start the (already-stopped) Python agents pointing at the new server.

The Go server's web UI is on the same port range Python natlas used (5001
in dev compose), so most reverse proxy configs need only the upstream
hostname change.

## Rollback

If something is wrong post-cutover:

1. Repoint traffic back to the Python server.
2. Restart Python agents with their original `NATLAS_SERVER_ADDRESS`.

The migration is read-only against the source — Python natlas is in the
exact state it was before the run. Drop the destination DB + OpenSearch
indices to retry the migration cleanly later (or fix the migrator and
rerun; the natural-key dedup means re-imports are safe).

## Post-migration cleanup

- Re-issue any pending user invitations.
- Re-tag scope rows if you used tags (see "What does NOT get migrated").
- Snapshot the new OpenSearch indices and start a regular cadence.
- If you want fresh agent tokens (e.g. you suspect token leakage from the
  Python-era plaintext storage), rotate every agent with
  `natlas-admin agent rotate-token`.
- Decommission the old MinIO / Elasticsearch / Postgres / Python server
  hosts on whatever schedule your team prefers.
