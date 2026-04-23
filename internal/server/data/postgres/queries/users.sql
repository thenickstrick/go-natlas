-- name: UserCreate :one
INSERT INTO users (email, password_hash, is_admin, is_active)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: UserGetByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: UserGetByID :one
SELECT * FROM users WHERE id = $1;

-- name: UserList :many
SELECT * FROM users ORDER BY id ASC LIMIT $1 OFFSET $2;

-- name: UserCount :one
SELECT COUNT(*) FROM users;

-- name: UserSetAdmin :exec
UPDATE users SET is_admin = $2 WHERE id = $1;

-- name: UserSetPasswordHash :exec
UPDATE users SET password_hash = $2 WHERE id = $1;

-- name: UserDelete :exec
DELETE FROM users WHERE id = $1;
