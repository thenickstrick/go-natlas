-- name: UserCreate :one
INSERT INTO users (email, password_hash, is_admin, is_active)
VALUES (?, ?, ?, ?)
RETURNING *;

-- name: UserGetByEmail :one
SELECT * FROM users WHERE email = ?;

-- name: UserGetByID :one
SELECT * FROM users WHERE id = ?;

-- name: UserList :many
SELECT * FROM users ORDER BY id ASC LIMIT ? OFFSET ?;

-- name: UserCount :one
SELECT COUNT(*) FROM users;

-- name: UserSetAdmin :exec
UPDATE users SET is_admin = ? WHERE id = ?;

-- name: UserSetPasswordHash :exec
UPDATE users SET password_hash = ? WHERE id = ?;

-- name: UserDelete :exec
DELETE FROM users WHERE id = ?;
