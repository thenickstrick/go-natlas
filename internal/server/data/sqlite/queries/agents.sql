-- name: AgentCreate :one
INSERT INTO agents (user_id, agent_id, token_hash, friendly_name)
VALUES (?, ?, ?, ?)
RETURNING *;

-- name: AgentGetByAgentID :one
SELECT * FROM agents WHERE agent_id = ?;

-- name: AgentListByUser :many
SELECT * FROM agents WHERE user_id = ? ORDER BY id ASC;

-- name: AgentListAll :many
SELECT * FROM agents ORDER BY id ASC;

-- name: AgentSetTokenHash :exec
UPDATE agents SET token_hash = ? WHERE id = ?;

-- name: AgentSetFriendlyName :exec
UPDATE agents SET friendly_name = ? WHERE id = ?;

-- name: AgentTouchLastSeen :exec
UPDATE agents SET last_seen_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?;

-- name: AgentDelete :exec
DELETE FROM agents WHERE id = ?;
