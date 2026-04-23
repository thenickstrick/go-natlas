-- name: RescanTaskCreate :one
INSERT INTO rescan_tasks (user_id, target)
VALUES (?, ?)
RETURNING *;

-- name: RescanTaskGetByID :one
SELECT * FROM rescan_tasks WHERE id = ?;

-- SQLite has no FOR UPDATE SKIP LOCKED; transaction-level BEGIN IMMEDIATE and
-- the pending_idx give us the same guarantee with only serialized writers.
-- name: RescanTaskNextPending :one
SELECT * FROM rescan_tasks
WHERE dispatched_at IS NULL AND completed_at IS NULL
ORDER BY created_at ASC
LIMIT 1;

-- name: RescanTaskDispatch :exec
UPDATE rescan_tasks SET dispatched_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?;

-- name: RescanTaskComplete :exec
UPDATE rescan_tasks
SET completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), scan_id = ?
WHERE id = ?;

-- name: RescanTaskReapStale :many
UPDATE rescan_tasks
SET dispatched_at = NULL
WHERE dispatched_at IS NOT NULL
  AND completed_at IS NULL
  AND dispatched_at < ?
RETURNING id;

-- name: RescanTaskListForUser :many
SELECT * FROM rescan_tasks WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?;
