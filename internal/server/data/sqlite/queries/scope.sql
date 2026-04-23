-- name: ScopeItemCreate :one
INSERT INTO scope_items (cidr, is_blacklist, start_addr, stop_addr)
VALUES (?, ?, ?, ?)
ON CONFLICT (cidr, is_blacklist) DO UPDATE SET cidr = excluded.cidr
RETURNING *;

-- name: ScopeItemGetByID :one
SELECT * FROM scope_items WHERE id = ?;

-- name: ScopeItemList :many
SELECT * FROM scope_items WHERE is_blacklist = ? ORDER BY start_addr ASC;

-- name: ScopeItemListAll :many
SELECT * FROM scope_items ORDER BY is_blacklist ASC, start_addr ASC;

-- name: ScopeItemDelete :exec
DELETE FROM scope_items WHERE id = ?;

-- name: TagCreate :one
INSERT INTO tags (name) VALUES (?)
ON CONFLICT (name) DO UPDATE SET name = excluded.name
RETURNING *;

-- name: TagListForScopeItem :many
SELECT t.* FROM tags t
JOIN scope_item_tags st ON st.tag_id = t.id
WHERE st.scope_item_id = ?
ORDER BY t.name ASC;

-- name: ScopeItemAddTag :exec
INSERT INTO scope_item_tags (scope_item_id, tag_id)
VALUES (?, ?)
ON CONFLICT DO NOTHING;

-- name: ScopeLogAppend :exec
INSERT INTO scope_log (message) VALUES (?);
