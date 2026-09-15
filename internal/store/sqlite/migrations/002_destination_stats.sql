-- 002_destination_stats.sql — per-destination traffic monitoring (Phase 7).
--
-- One row per (user, day, host, port, protocol): aggregated counters only,
-- written by the low-frequency batch flush, never per request. The host is
-- the destination exactly as the client requested it (hostname when
-- available, else the resolved IP) — never decrypted content, which the
-- control plane cannot and does not capture.

CREATE TABLE destination_stats (
    user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    day       TEXT    NOT NULL,        -- YYYY-MM-DD, UTC
    host      TEXT    NOT NULL,        -- destination hostname or IP as requested
    port      INTEGER NOT NULL,
    protocol  TEXT    NOT NULL CHECK (protocol IN ('http','https','socks5')),
    requests  INTEGER NOT NULL DEFAULT 0,
    blocked   INTEGER NOT NULL DEFAULT 0,  -- requests refused by policy/quota (engine error != 0)
    bytes_in  INTEGER NOT NULL DEFAULT 0,  -- downloads (from target)
    bytes_out INTEGER NOT NULL DEFAULT 0,  -- uploads (to target)
    last_seen TEXT    NOT NULL,
    PRIMARY KEY (user_id, day, host, port, protocol)
);

CREATE INDEX idx_destination_stats_day ON destination_stats(day);
CREATE INDEX idx_destination_stats_user_day ON destination_stats(user_id, day);
