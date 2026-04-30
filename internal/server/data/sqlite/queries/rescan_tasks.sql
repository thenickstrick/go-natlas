-- name: RescanTaskCreate :one
INSERT INTO rescan_tasks (user_id, target)
VALUES (?, ?)
RETURNING *;

-- name: RescanTaskGetByID :one
SELECT * FROM rescan_tasks WHERE id = ?;

-- SQLite has no FOR UPDATE SKIP LOCKED; serialize writes via BEGIN IMMEDIATE
-- transactions at the application layer instead. The pending_idx covers this.
-- name: RescanTaskNextPending :one
SELECT * FROM rescan_tasks
WHERE dispatched_at IS NULL AND completed_at IS NULL
ORDER BY created_at ASC
LIMIT 1;

-- name: RescanTaskDispatch :exec
UPDATE rescan_tasks
SET dispatched_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), scan_id = ?
WHERE id = ?;

-- name: RescanTaskCompleteByScanID :execrows
UPDATE rescan_tasks
SET completed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE scan_id = ? AND completed_at IS NULL;

-- name: RescanTaskReapStale :many
UPDATE rescan_tasks
SET dispatched_at = NULL, scan_id = NULL
WHERE dispatched_at IS NOT NULL
  AND completed_at IS NULL
  AND dispatched_at < ?
RETURNING id;

-- name: RescanTaskListForUser :many
SELECT * FROM rescan_tasks WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?;
