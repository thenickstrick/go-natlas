-- name: AgentCreate :one
INSERT INTO agents (user_id, agent_id, token_hash, friendly_name)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: AgentGetByAgentID :one
SELECT * FROM agents WHERE agent_id = $1;

-- name: AgentListByUser :many
SELECT * FROM agents WHERE user_id = $1 ORDER BY id ASC;

-- name: AgentListAll :many
SELECT * FROM agents ORDER BY id ASC;

-- name: AgentSetTokenHash :exec
UPDATE agents SET token_hash = $2 WHERE id = $1;

-- name: AgentSetFriendlyName :exec
UPDATE agents SET friendly_name = $2 WHERE id = $1;

-- name: AgentTouchLastSeen :exec
UPDATE agents SET last_seen_at = NOW() WHERE id = $1;

-- name: AgentDelete :exec
DELETE FROM agents WHERE id = $1;
