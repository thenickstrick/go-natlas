#!/bin/sh
# One-shot Garage bootstrap. Runs as a sidecar with the same config mounted as
# the main garage container. Assigns the node a layout role, applies it, creates
# the natlas-screenshots bucket, and imports a deterministic dev key. All
# operations are idempotent so this can safely run on every compose-up.
#
# Fixed dev credentials — DO NOT reuse in production.
set -eu

GARAGE="/garage"
export GARAGE_RPC_HOST="garage:3901"
export GARAGE_RPC_SECRET="a7e1ffcd3a9bce1a3e96e1b9a6a7f6d2c5e9b1a3e96e1b9a6a7f6d2c5e9b1a3c"

echo "[garage-init] waiting for garage RPC..."
i=0
until $GARAGE status >/dev/null 2>&1; do
    i=$((i + 1))
    if [ $i -gt 60 ]; then
        echo "[garage-init] garage never came up" >&2
        exit 1
    fi
    sleep 2
done
echo "[garage-init] garage is reachable"

# Ensure the local node has a role in the cluster layout.
if ! $GARAGE layout show 2>/dev/null | grep -q 'Current cluster layout version'; then
    NODE_ID="$($GARAGE status | awk 'NR>1 && $1 ~ /^[0-9a-f]+$/ {print $1; exit}')"
    if [ -z "${NODE_ID}" ]; then
        echo "[garage-init] could not determine node id from `garage status`" >&2
        $GARAGE status >&2
        exit 1
    fi
    echo "[garage-init] assigning layout to node ${NODE_ID}"
    $GARAGE layout assign -z dc1 -c 1G "${NODE_ID}"
    $GARAGE layout apply --version 1
else
    echo "[garage-init] layout already applied"
fi

# Ensure bucket exists.
$GARAGE bucket create natlas-screenshots 2>/dev/null || true

# Import a deterministic dev key. Key ID must be GK + 30 hex-like chars;
# secret must be 64 chars. Values below match those referenced in
# deploy/docker-compose.yml under the `server` service.
$GARAGE key import \
    --yes \
    GKnatlas00000000000000000000dev01 \
    natlas0000000000000000000000000000000000000000000000000000dev01 \
    --name natlas-dev 2>/dev/null || true

$GARAGE bucket allow --read --write --owner natlas-screenshots --key natlas-dev

echo "[garage-init] done"
$GARAGE key info natlas-dev || true
