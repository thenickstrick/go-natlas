-- name: RescanTaskCreate :one
INSERT INTO rescan_tasks (user_id, target)
VALUES ($1, $2)
RETURNING *;

-- name: RescanTaskGetByID :one
SELECT * FROM rescan_tasks WHERE id = $1;

-- name: RescanTaskNextPending :one
SELECT * FROM rescan_tasks
WHERE dispatched_at IS NULL AND completed_at IS NULL
ORDER BY created_at ASC
FOR UPDATE SKIP LOCKED
LIMIT 1;

-- name: RescanTaskDispatch :exec
UPDATE rescan_tasks SET dispatched_at = NOW() WHERE id = $1;

-- name: RescanTaskComplete :exec
UPDATE rescan_tasks SET completed_at = NOW(), scan_id = $2 WHERE id = $1;

-- name: RescanTaskReapStale :many
UPDATE rescan_tasks
SET dispatched_at = NULL
WHERE dispatched_at IS NOT NULL
  AND completed_at IS NULL
  AND dispatched_at < $1
RETURNING id;

-- name: RescanTaskListForUser :many
SELECT * FROM rescan_tasks WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3;
