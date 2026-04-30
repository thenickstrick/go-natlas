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

-- RescanTaskDispatch records the dispatch event AND the scan_id minted for it.
-- The scan_id is the link that lets a later POST /api/v1/results find this row
-- without an additional query, via RescanTaskCompleteByScanID below.
-- name: RescanTaskDispatch :exec
UPDATE rescan_tasks
SET dispatched_at = NOW(), scan_id = $2
WHERE id = $1;

-- RescanTaskCompleteByScanID closes out the rescan whose scan_id matches the
-- submitted result. completed_at IS NULL guard prevents double-completion if
-- the same result is submitted twice.
-- name: RescanTaskCompleteByScanID :execrows
UPDATE rescan_tasks
SET completed_at = NOW()
WHERE scan_id = $1 AND completed_at IS NULL;

-- RescanTaskReapStale clears the dispatch state on tasks that were dispatched
-- but never reported back. The scan_id is also cleared so that a fresh
-- dispatch is free to mint a new one — a late-arriving result for the old
-- scan_id has nothing to match and is silently ignored at the rescan layer
-- (the result still indexes into OpenSearch via the regular submission flow).
-- name: RescanTaskReapStale :many
UPDATE rescan_tasks
SET dispatched_at = NULL, scan_id = NULL
WHERE dispatched_at IS NOT NULL
  AND completed_at IS NULL
  AND dispatched_at < $1
RETURNING id;

-- name: RescanTaskListForUser :many
SELECT * FROM rescan_tasks WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3;
