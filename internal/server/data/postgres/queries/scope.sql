-- name: ScopeItemCreate :one
INSERT INTO scope_items (cidr, is_blacklist, start_addr, stop_addr)
VALUES ($1, $2, $3, $4)
ON CONFLICT (cidr, is_blacklist) DO UPDATE SET cidr = EXCLUDED.cidr
RETURNING *;

-- name: ScopeItemGetByID :one
SELECT * FROM scope_items WHERE id = $1;

-- name: ScopeItemList :many
SELECT * FROM scope_items WHERE is_blacklist = $1 ORDER BY start_addr ASC;

-- name: ScopeItemListAll :many
SELECT * FROM scope_items ORDER BY is_blacklist ASC, start_addr ASC;

-- name: ScopeItemDelete :exec
DELETE FROM scope_items WHERE id = $1;

-- name: TagCreate :one
INSERT INTO tags (name) VALUES ($1)
ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
RETURNING *;

-- name: TagListForScopeItem :many
SELECT t.* FROM tags t
JOIN scope_item_tags st ON st.tag_id = t.id
WHERE st.scope_item_id = $1
ORDER BY t.name ASC;

-- name: ScopeItemAddTag :exec
INSERT INTO scope_item_tags (scope_item_id, tag_id)
VALUES ($1, $2)
ON CONFLICT DO NOTHING;

-- name: ScopeLogAppend :exec
INSERT INTO scope_log (message) VALUES ($1);
