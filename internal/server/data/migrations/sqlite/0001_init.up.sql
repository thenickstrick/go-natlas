-- 0001_init: SQLite mirror of the Postgres schema.
-- * BIGSERIAL            -> INTEGER PRIMARY KEY (SQLite autoincrements rowid)
-- * TIMESTAMPTZ + NOW()  -> TEXT in ISO8601 UTC (strftime with ms precision)
-- * BOOLEAN              -> INTEGER (0/1); SQLite accepts BOOLEAN as an alias
-- * CIDR / INET          -> TEXT (canonical form written by netip.String())
-- * TEXT[]               -> TEXT (JSON-encoded; application serializes)
-- * CHECK / REFERENCES   -> preserved; FK enforcement is turned on in Go.

CREATE TABLE users (
    id                        INTEGER PRIMARY KEY,
    email                     TEXT NOT NULL UNIQUE,
    password_hash             TEXT NOT NULL,
    is_admin                  INTEGER NOT NULL DEFAULT 0,
    results_per_page          INTEGER NOT NULL DEFAULT 100,
    preview_length            INTEGER NOT NULL DEFAULT 100,
    result_format             INTEGER NOT NULL DEFAULT 0,
    password_reset_token      TEXT,
    password_reset_expires_at TEXT,
    created_at                TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    is_active                 INTEGER NOT NULL DEFAULT 1
);
CREATE UNIQUE INDEX users_password_reset_token_key
    ON users (password_reset_token)
    WHERE password_reset_token IS NOT NULL;

CREATE TABLE agents (
    id            INTEGER PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    agent_id      TEXT NOT NULL UNIQUE,
    token_hash    TEXT NOT NULL,
    friendly_name TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_seen_at  TEXT
);
CREATE INDEX agents_user_id_idx ON agents (user_id);

CREATE TABLE scope_items (
    id           INTEGER PRIMARY KEY,
    cidr         TEXT NOT NULL,
    is_blacklist INTEGER NOT NULL DEFAULT 0,
    start_addr   TEXT NOT NULL,
    stop_addr    TEXT NOT NULL,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (cidr, is_blacklist)
);
CREATE INDEX scope_items_blacklist_idx ON scope_items (is_blacklist);

CREATE TABLE tags (
    id   INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE scope_item_tags (
    scope_item_id INTEGER NOT NULL REFERENCES scope_items(id) ON DELETE CASCADE,
    tag_id        INTEGER NOT NULL REFERENCES tags(id)        ON DELETE CASCADE,
    PRIMARY KEY (scope_item_id, tag_id)
);

CREATE TABLE rescan_tasks (
    id            INTEGER PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target        TEXT NOT NULL,
    scan_id       TEXT UNIQUE,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    dispatched_at TEXT,
    completed_at  TEXT
);
CREATE INDEX rescan_tasks_pending_idx
    ON rescan_tasks (created_at)
    WHERE dispatched_at IS NULL AND completed_at IS NULL;
CREATE INDEX rescan_tasks_stale_idx
    ON rescan_tasks (dispatched_at)
    WHERE dispatched_at IS NOT NULL AND completed_at IS NULL;

CREATE TABLE agent_config (
    id                       INTEGER PRIMARY KEY DEFAULT 1,
    version_detection        INTEGER NOT NULL DEFAULT 1,
    os_detection             INTEGER NOT NULL DEFAULT 1,
    enable_scripts           INTEGER NOT NULL DEFAULT 1,
    only_opens               INTEGER NOT NULL DEFAULT 1,
    scan_timeout_s           INTEGER NOT NULL DEFAULT 660,
    web_screenshots          INTEGER NOT NULL DEFAULT 1,
    vnc_screenshots          INTEGER NOT NULL DEFAULT 1,
    web_screenshot_timeout_s INTEGER NOT NULL DEFAULT 60,
    vnc_screenshot_timeout_s INTEGER NOT NULL DEFAULT 60,
    script_timeout_s         INTEGER NOT NULL DEFAULT 60,
    host_timeout_s           INTEGER NOT NULL DEFAULT 600,
    os_scan_limit            INTEGER NOT NULL DEFAULT 1,
    no_ping                  INTEGER NOT NULL DEFAULT 0,
    udp_scan                 INTEGER NOT NULL DEFAULT 0,
    scripts                  TEXT    NOT NULL DEFAULT '["default"]',
    CHECK (id = 1)
);
INSERT INTO agent_config (id) VALUES (1);

CREATE TABLE natlas_services (
    id         INTEGER PRIMARY KEY DEFAULT 1,
    sha256     TEXT NOT NULL DEFAULT '',
    services   TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (id = 1)
);
INSERT INTO natlas_services (id) VALUES (1);

CREATE TABLE scope_log (
    id      INTEGER PRIMARY KEY,
    ts      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    message TEXT NOT NULL
);
CREATE INDEX scope_log_ts_idx ON scope_log (ts DESC);

CREATE TABLE user_invitations (
    id           INTEGER PRIMARY KEY,
    email        TEXT NOT NULL UNIQUE,
    is_admin     INTEGER NOT NULL DEFAULT 0,
    invite_token TEXT NOT NULL UNIQUE,
    invited_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at   TEXT NOT NULL,
    accepted     INTEGER NOT NULL DEFAULT 0
);
