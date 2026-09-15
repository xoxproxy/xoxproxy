-- 001_initial.sql — initial xoxproxy schema.
--
-- Conventions: timestamps are RFC 3339 (UTC) text; byte counters and limits
-- are INTEGER (int64); migrations are forward-only.
--
-- The users/credentials/usage_periods/configuration_versions tables are the
-- Phase 1 schema deliverable; their repositories land in Phases 5-7. Schema
-- changes after this file always ship as new numbered migrations.

CREATE TABLE admin_accounts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash   TEXT    NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL
);

CREATE TABLE admin_sessions (
    id           TEXT PRIMARY KEY,
    account_id   INTEGER NOT NULL REFERENCES admin_accounts(id) ON DELETE CASCADE,
    token_hash   TEXT    NOT NULL UNIQUE,
    csrf_token   TEXT    NOT NULL,
    created_at   TEXT    NOT NULL,
    expires_at   TEXT    NOT NULL,
    last_seen_at TEXT    NOT NULL,
    source_ip    TEXT    NOT NULL DEFAULT '',
    user_agent   TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX idx_admin_sessions_expires ON admin_sessions(expires_at);
CREATE INDEX idx_admin_sessions_account ON admin_sessions(account_id);

CREATE TABLE audit_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    target     TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL DEFAULT '',
    source_ip  TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    result     TEXT NOT NULL,
    detail     TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_audit_logs_action ON audit_logs(action);

CREATE TABLE users (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id          TEXT    NOT NULL DEFAULT 'local',
    username           TEXT    NOT NULL UNIQUE,
    status             TEXT    NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active','disabled','expired')),
    allowed_protocols  TEXT    NOT NULL DEFAULT 'http,socks5',
    download_limit_bps INTEGER NOT NULL DEFAULT 0,
    upload_limit_bps   INTEGER NOT NULL DEFAULT 0,
    max_connections    INTEGER NOT NULL DEFAULT 0,
    quota_bytes_daily  INTEGER NOT NULL DEFAULT 0,
    quota_bytes_monthly INTEGER NOT NULL DEFAULT 0,
    expires_at         TEXT,
    version            INTEGER NOT NULL DEFAULT 1,
    created_at         TEXT    NOT NULL,
    updated_at         TEXT    NOT NULL,
    last_seen_at       TEXT
);

CREATE INDEX idx_users_status ON users(status);

CREATE TABLE credentials (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    engine_hash TEXT    NOT NULL,
    api_hash    TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active','revoked')),
    created_at  TEXT    NOT NULL,
    rotated_at  TEXT
);

CREATE INDEX idx_credentials_user ON credentials(user_id);

CREATE TABLE usage_periods (
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    period_start TEXT    NOT NULL,
    granularity  TEXT    NOT NULL CHECK (granularity IN ('hour','day','month')),
    bytes_in     INTEGER NOT NULL DEFAULT 0,
    bytes_out    INTEGER NOT NULL DEFAULT 0,
    connections  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, period_start, granularity)
);

CREATE TABLE configuration_versions (
    revision           INTEGER PRIMARY KEY AUTOINCREMENT,
    generated_at       TEXT NOT NULL,
    generated_by       TEXT NOT NULL,
    reason             TEXT NOT NULL,
    validation_status  TEXT NOT NULL,
    deployment_status  TEXT NOT NULL,
    checksum           TEXT NOT NULL
);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
