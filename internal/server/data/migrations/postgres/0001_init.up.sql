-- 0001_init: initial schema for the natlas control plane.
-- All IP columns use native inet/cidr; timestamps are timestamptz; text is
-- unbounded — byte-length constraints are enforced by the application layer.

CREATE TABLE users (
    id                        BIGSERIAL PRIMARY KEY,
    email                     TEXT NOT NULL UNIQUE,
    password_hash             TEXT NOT NULL,
    is_admin                  BOOLEAN NOT NULL DEFAULT FALSE,
    results_per_page          INTEGER NOT NULL DEFAULT 100,
    preview_length            INTEGER NOT NULL DEFAULT 100,
    result_format             INTEGER NOT NULL DEFAULT 0,
    password_reset_token      TEXT,
    password_reset_expires_at TIMESTAMPTZ,
    created_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active                 BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE UNIQUE INDEX users_password_reset_token_key
    ON users (password_reset_token)
    WHERE password_reset_token IS NOT NULL;

CREATE TABLE agents (
    id            BIGSERIAL PRIMARY KEY,
    user_id       BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    agent_id      TEXT NOT NULL UNIQUE,
    token_hash    TEXT NOT NULL,
    friendly_name TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at  TIMESTAMPTZ
);
CREATE INDEX agents_user_id_idx ON agents (user_id);

CREATE TABLE scope_items (
    id           BIGSERIAL PRIMARY KEY,
    cidr         CIDR NOT NULL,
    is_blacklist BOOLEAN NOT NULL DEFAULT FALSE,
    start_addr   INET NOT NULL,
    stop_addr    INET NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (cidr, is_blacklist)
);
CREATE INDEX scope_items_blacklist_idx ON scope_items (is_blacklist);
CREATE INDEX scope_items_cidr_gist ON scope_items USING gist (cidr inet_ops);

CREATE TABLE tags (
    id   BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE scope_item_tags (
    scope_item_id BIGINT NOT NULL REFERENCES scope_items(id) ON DELETE CASCADE,
    tag_id        BIGINT NOT NULL REFERENCES tags(id)        ON DELETE CASCADE,
    PRIMARY KEY (scope_item_id, tag_id)
);

CREATE TABLE rescan_tasks (
    id            BIGSERIAL PRIMARY KEY,
    user_id       BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target        INET   NOT NULL,
    scan_id       TEXT UNIQUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    dispatched_at TIMESTAMPTZ,
    completed_at  TIMESTAMPTZ
);
-- Covers the "next pending rescan" dispatch query.
CREATE INDEX rescan_tasks_pending_idx
    ON rescan_tasks (created_at)
    WHERE dispatched_at IS NULL AND completed_at IS NULL;
-- Covers the "reap stale dispatches" query.
CREATE INDEX rescan_tasks_stale_idx
    ON rescan_tasks (dispatched_at)
    WHERE dispatched_at IS NOT NULL AND completed_at IS NULL;

-- Singleton: the single row of dispatcher config all agents see.
CREATE TABLE agent_config (
    id                       INTEGER PRIMARY KEY DEFAULT 1,
    version_detection        BOOLEAN NOT NULL DEFAULT TRUE,
    os_detection             BOOLEAN NOT NULL DEFAULT TRUE,
    enable_scripts           BOOLEAN NOT NULL DEFAULT TRUE,
    only_opens               BOOLEAN NOT NULL DEFAULT TRUE,
    scan_timeout_s           INTEGER NOT NULL DEFAULT 660,
    web_screenshots          BOOLEAN NOT NULL DEFAULT TRUE,
    vnc_screenshots          BOOLEAN NOT NULL DEFAULT TRUE,
    web_screenshot_timeout_s INTEGER NOT NULL DEFAULT 60,
    vnc_screenshot_timeout_s INTEGER NOT NULL DEFAULT 60,
    script_timeout_s         INTEGER NOT NULL DEFAULT 60,
    host_timeout_s           INTEGER NOT NULL DEFAULT 600,
    os_scan_limit            BOOLEAN NOT NULL DEFAULT TRUE,
    no_ping                  BOOLEAN NOT NULL DEFAULT FALSE,
    udp_scan                 BOOLEAN NOT NULL DEFAULT FALSE,
    scripts                  TEXT[]  NOT NULL DEFAULT ARRAY['default']::TEXT[],
    CHECK (id = 1)
);
INSERT INTO agent_config (id) VALUES (1);

-- Singleton: the custom nmap services DB + its sha256.
CREATE TABLE natlas_services (
    id         INTEGER PRIMARY KEY DEFAULT 1,
    sha256     TEXT NOT NULL DEFAULT '',
    services   TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (id = 1)
);
INSERT INTO natlas_services (id) VALUES (1);

-- Operational event log (PRNG cycle boundaries, scope changes, etc.).
CREATE TABLE scope_log (
    id      BIGSERIAL PRIMARY KEY,
    ts      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    message TEXT NOT NULL
);
CREATE INDEX scope_log_ts_idx ON scope_log (ts DESC);

CREATE TABLE user_invitations (
    id           BIGSERIAL PRIMARY KEY,
    email        TEXT    NOT NULL UNIQUE,
    is_admin     BOOLEAN NOT NULL DEFAULT FALSE,
    invite_token TEXT    NOT NULL UNIQUE,
    invited_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL,
    accepted     BOOLEAN NOT NULL DEFAULT FALSE
);
