#!/bin/sh
# One-shot Garage bootstrap. Runs as a sidecar in a curl-image container —
# Garage's own image is FROM scratch and has no shell, so we drive the
# bootstrap through the admin HTTP API instead of the `garage` CLI.
#
# Operations are idempotent so this can safely run on every compose-up:
#   1. wait for garage's admin port to answer
#   2. assign the local node a layout role (no-op if already assigned)
#   3. apply the layout (no-op once committed)
#   4. ensure the natlas-screenshots bucket exists
#   5. import a deterministic dev key (no-op if a key by that name exists)
#   6. grant the key read+write on the bucket
#
# Fixed dev credentials — DO NOT reuse in production.
set -eu

GARAGE="http://garage:3902"
ADMIN_TOKEN="natlas-dev-admin-token"

# Garage v1 access key format: literal "GK" + 24 hex-encoded chars (12 bytes).
# Secret: 32 hex-encoded bytes (64 chars). The values are deterministic so
# the server's compose env can hardcode them — they are dev-only.
KEY_ID="GKa1b2c3d4e5f6a1b2c3d4e5f6"
SECRET_KEY="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
KEY_NAME="natlas-dev"
BUCKET="natlas-screenshots"

# Plain alpine: install both curl and jq up front. The image is small so
# the cold-start cost is a few seconds.
if ! command -v jq >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
    echo "[garage-init] installing curl + jq..."
    apk add --no-cache curl jq >/dev/null
fi

curl_admin() {
    method="$1"
    path="$2"
    body="${3:-}"
    # No -f: we want to see the response body for debugging when Garage 400s.
    if [ -n "$body" ]; then
        curl -sS -X "$method" \
            -H "Authorization: Bearer $ADMIN_TOKEN" \
            -H "Content-Type: application/json" \
            -d "$body" \
            "$GARAGE$path"
    else
        curl -sS -X "$method" \
            -H "Authorization: Bearer $ADMIN_TOKEN" \
            "$GARAGE$path"
    fi
}

echo "[garage-init] waiting for garage admin API..."
i=0
until curl -fsS -H "Authorization: Bearer $ADMIN_TOKEN" "$GARAGE/v1/health" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -gt 60 ]; then
        echo "[garage-init] garage admin API never came up" >&2
        exit 1
    fi
    sleep 2
done
echo "[garage-init] admin API reachable"

STATUS_JSON="$(curl_admin GET /v1/status)"
NODE_ID="$(echo "$STATUS_JSON" | jq -r '.node // (.nodes[0].id // empty)')"
if [ -z "$NODE_ID" ] || [ "$NODE_ID" = "null" ]; then
    echo "[garage-init] could not discover node id from /v1/status" >&2
    echo "$STATUS_JSON" >&2
    exit 1
fi
echo "[garage-init] node id: $NODE_ID"

# Stage a role for the node. The POST body is the list of nodes that should
# have roles; resending the same payload is a no-op.
echo "[garage-init] staging layout role..."
curl_admin POST /v1/layout \
    "[{\"id\":\"$NODE_ID\",\"zone\":\"dc1\",\"capacity\":1000000000,\"tags\":[]}]" \
    >/dev/null

# Apply the staged change. The `version` field is the version we expect to
# *result*, i.e. (currentVersion + 1). When nothing's staged this 4xxs;
# treat that as a noop.
LAYOUT_JSON="$(curl_admin GET /v1/layout)"
CURRENT_VERSION="$(echo "$LAYOUT_JSON" | jq -r '.version // 0')"
NEXT_VERSION=$((CURRENT_VERSION + 1))
echo "[garage-init] applying layout v$NEXT_VERSION..."
curl_admin POST /v1/layout/apply "{\"version\":$NEXT_VERSION}" >/dev/null 2>&1 || \
    echo "[garage-init] layout apply was a noop (already at the staged version)"

echo "[garage-init] ensuring bucket $BUCKET..."
curl_admin POST /v1/bucket "{\"globalAlias\":\"$BUCKET\"}" >/dev/null 2>&1 || true

echo "[garage-init] importing dev key (deterministic creds for compose)..."
KEY_RESP="$(curl_admin POST /v1/key/import \
    "{\"accessKeyId\":\"$KEY_ID\",\"secretAccessKey\":\"$SECRET_KEY\",\"name\":\"$KEY_NAME\"}")"
echo "[garage-init]   import response: $KEY_RESP"

BUCKET_INFO="$(curl_admin GET "/v1/bucket?globalAlias=$BUCKET")"
BUCKET_ID="$(echo "$BUCKET_INFO" | jq -r '.id // empty')"
if [ -n "$BUCKET_ID" ]; then
    echo "[garage-init] granting key R/W on bucket $BUCKET_ID..."
    ALLOW_RESP="$(curl_admin POST /v1/bucket/allow \
        "{\"bucketId\":\"$BUCKET_ID\",\"accessKeyId\":\"$KEY_ID\",\"permissions\":{\"read\":true,\"write\":true,\"owner\":true}}")"
    echo "[garage-init]   allow response: $ALLOW_RESP"
else
    echo "[garage-init] could not look up bucket id; permission grant skipped" >&2
fi

echo "[garage-init] bootstrap complete:"
echo "  bucket:     $BUCKET"
echo "  access key: $KEY_ID"
echo "  secret:     (in compose env)"
