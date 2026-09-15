# Architecture — xoxproxy

> Phase 1 deliverable. Risk register and tradeoffs: [DESIGN-REVIEW.md](DESIGN-REVIEW.md).
> Adversary analysis: [THREAT-MODEL.md](THREAT-MODEL.md).

xoxproxy is a self-hosted proxy management appliance: a single Go binary
(control plane) that manages a 3proxy data plane on one Linux VPS, with a
React dashboard, authenticated HTTP/SOCKS5 proxy users, bandwidth limits,
quotas, expiration, analytics, and automated installation.

---

## 1. Core Principle

**The data plane must not depend on the control plane.**

3proxy serves traffic from two files on disk (its config and its users file).
The control plane's entire job is to keep those files correct — safely,
atomically, and verifiably. If every Go process dies, the proxy keeps
forwarding bytes until the VPS itself reboots (and on reboot, systemd starts
the engine from the same files before anything else needs to be healthy).

There is **no** channel from the engine's request path to the database, the
API, or the dashboard. Not "a fast channel" — no channel.

---

## 2. Component Overview

```
                        Internet
                           |
                   +---------------+
                   |    Firewall   |  nftables (inet xoxproxy table)
                   +-------+-------+
                           |
         +-----------------+------------------+
         |                                    |
         v                                    v
  +--------------+                 +---------------------+
  |  3proxy      |  data plane     |  Caddy (optional)   |
  |  xoxproxy-   |  systemd unit:  |  TLS termination    |
  |  engine      |  xoxproxy-      |  for dashboard      |
  |              |  engine.service +----------+----------+
  | :3128 HTTP   |                            |
  | :1080 SOCKS5 |                 +----------v----------+
  +---+----------+                 |  xoxproxy (Go)      |  control plane
      |                            |  - REST API /api/v1 |
      | structured log ------------>|  - dashboard (embed)|
      | counters file               |  - SSE stream       |
      |                            |  - jobs             |
      |  127.0.0.1 mgmt socket <---|  - log tailer       |
      |  (reload users)            |  - metrics /metrics |
      +----------------------------|  - SQLite (WAL)     |
                                   +---------------------+
```

| Component | Process | User | Failure scope |
|---|---|---|---|
| 3proxy engine | `xoxproxy-engine.service` | `xoxproxy` (unprivileged) | Proxy traffic stops; nothing else |
| xoxproxy control plane | `xoxproxy.service` | `xoxproxy` | Dashboard/API/analytics stop; proxy traffic unaffected |
| Caddy (optional TLS) | `xoxproxy-web.service` or Caddy package unit | `caddy` | Dashboard unreachable; proxy traffic unaffected |
| SQLite | in-process (control plane) | file ownership | Control-plane persistence stops; traffic unaffected |
| nftables | kernel | rules in `inet xoxproxy` table | Misconfiguration risks SSH/ports — mitigated by R9 |

---

## 3. Control Plane (Go binary)

Single binary, multiple roles:

```
xoxproxy server        start the control plane (API + dashboard + jobs)
xoxproxy users list    admin CLI (same service layer as the API)
xoxproxy proxy reload
xoxproxy config validate / rollback
xoxproxy firewall ...
xoxproxy update / backup / uninstall
```

### 3.1 Package layout

```
cmd/xoxproxy/           main: CLI dispatch + server bootstrap
internal/
    api/                HTTP layer: routing, middleware, SSE, error envelope
    auth/               admin sessions, CSRF, login throttling, argon2id
    domain/             entities + rules: users, quotas, bandwidth, expiration
                        (no I/O, no engine syntax — pure logic, fully unit-tested)
    engine/             ProxyEngine interface + orchestration (deploy pipeline)
    engine/threeproxy/  3proxy provider: config generation, validation,
                        lifecycle, management client, log/counter parsing
    config/             app configuration loading + validation
    deploy/             atomic file deployment: generate → validate → stage →
                        rename → reload → verify → rollback (single-flight)
    store/              repository interfaces (users, usage, audit, sessions,
                        settings, config_versions)
    store/sqlite/       SQLite implementation + migrations
    analytics/          log tailer → bounded queues → coalescing counters →
                        periodic flush; rollup jobs
    metrics/            Prometheus exposition
    jobs/               scheduler: reconciliation, quota reset, expiry,
                        rotation, health, cleanup (cancellable, bounded)
    system/             host telemetry (CPU/RAM/disk/net), service status,
                        public IP detection
    firewall/           nftables policy model + privileged-helper client
    updates/            self-upgrade, backups, restore
    audit/              audit log service (used by every privileged action)
    logging/            structured JSON logging, request IDs, redaction
web/                    React + TypeScript dashboard source (built into embed.FS)
```

Rules:
- `domain` imports nothing from this list except shared kernel types.
- `api` calls services; services call `domain` + `store` + `engine`; `api`
  never touches `store` or `engine` internals directly.
- CLI (`cmd`) calls the same services the API calls.

### 3.2 Request path (control plane)

```
request → logging middleware (request ID) → auth middleware (session)
        → rate limit → validation (bounded body) → handler
        → service layer → repositories / engine orchestrator
        → audit (privileged actions) → structured error envelope
```

Error envelope (never leaks internals):

```json
{ "error": { "code": "USER_NOT_FOUND", "message": "User not found",
             "request_id": "req_..." } }
```

### 3.3 Real-time updates

SSE endpoint `/api/v1/stream` with tiered cadence:
- fast tier (~2s): active connections, throughput, engine health
- slow tier (~15s): CPU/RAM/disk, user status rollups

One broadcaster goroutine; clients subscribe to snapshots computed from
aggregated counters (no per-client work, no high-cardinality payloads).

---

## 4. Data Plane (3proxy)

### 4.1 What the engine gets

Everything the engine needs is materialized as files before it runs:

| File | Contents | Written by |
|---|---|---|
| `/etc/xoxproxy/engine/3proxy.cfg` | listeners, auth mode, ACLs, bandwidth rules, counter config, log config, mgmt socket | deploy pipeline |
| `/etc/xoxproxy/engine/users.txt` | `user:CR:<hash>` entries | deploy pipeline |
| `/var/lib/xoxproxy/engine/counters` | persistent byte counters | 3proxy itself |
| `/var/log/xoxproxy/engine.log` | structured per-connection log | 3proxy itself |

The engine never reads the database, never calls the API, and is unaware the
control plane exists.

### 4.2 Generated config invariants

The generator guarantees, structurally (this is our validation layer, R2):

1. Every public listener has `auth strong` (HTTP/SOCKS5 user auth) — an
   anonymous listener is impossible to express without the audited
   `allow-anonymous` path.
2. Listeners bind explicit addresses covering both IPv4 and IPv6 (or IPv6
   explicitly disabled).
3. Per-user bandwidth: `bandlimin`/`bandlimout` rules derived from the user's
   limits (Mbps → bytes/sec, integer math).
4. Per-user connection caps and quota backstops (`countin`/`countout`) per
   spike results (R4).
5. Log format is machine-parseable and includes: timestamp, user, service,
   client IP, bytes in, bytes out, result.
6. Management socket binds `127.0.0.1:<random-free-port>` with a generated
   secret.

### 4.3 Deployment pipeline (single-flight)

```
current desired state (DB, single read tx)
        |
        v
   GenerateConfig ---------- failure ──> abort, alert, keep last-known-good
        |
        v
   Validate (invariants + port conflict check + staging boot check)
        |                                   │
        v                                   └─ failure ─> abort, alert, rollback
   write to temp file (same filesystem)
        |
        v
   fsync + atomic rename  (/etc/xoxproxy/engine/3proxy.cfg.new → .cfg)
        |
        v
   engine action: Reload (users-only) or Restart (structural)  [R1]
        |
        v
   health verify (engine alive, listeners bound, auth probe passes)
        |
     success ──> record config_version, audit, metrics
        |
     failure ─> restore last-known-good files, restart, alert
```

- One deploy at a time (mutex); concurrent requests coalesce into one
  deployment of the latest state (R7).
- Every deploy creates a `configuration_versions` row: revision, reason,
  generated_by, validation status, deployment status — enabling `config
  rollback` to revision N−1.
- Users-file-only changes (new user, rotate, disable, quota deny) deploy via
  management-interface reload without dropping connections. Anything touching
  listeners/ports/bandwidth rules is restart-class; the API response says so.

### 4.4 Traffic accounting (analytics path)

```
3proxy structured log ──tail──> parser ──> bounded queue (coalesce on overflow)
                                              |
                                              v
                                   in-memory counters (per user, per period)
                                              |
                        periodic flush (batched tx, integer uint64 upserts)
                                              |
                                              v
                        usage_periods (hourly rows) ──rollup──> daily/monthly
```

- The tailer is a control-plane process reading a file the engine appends to.
  If the tailer or DB dies, the log keeps growing (rotation caps it) and
  backfill is possible from the log — traffic never waits (R3, R6).
- Quota enforcement is belt-and-suspenders: engine-native limits where
  confirmed by the spike + a reconciliation job (every 60s) that denies
  over-quota users via users-file reload. Overrun is bounded by one interval.
- Expiration: same reconciliation job disables expired users regardless of
  dashboard state; expiry never depends on an admin being logged in.

---

## 5. Trust and Security Boundaries

```
 Internet ──(untrusted)──> engine auth (users file, per-connection)
 Internet ──(untrusted)──> dashboard auth (session, CSRF, rate-limited)
 control plane ──(local, trusted)──> engine mgmt socket (127.0.0.1, secret)
 control plane ──(local)──> privileged helper (fixed command vocabulary)
 control plane ──(local)──> SQLite, config files, logs
```

- The **engine** trusts only its files. Its attack surface is its own parser
  (mitigated: hardened systemd unit — `ProtectSystem=strict`,
  `NoNewPrivileges`, private `/tmp`, capability-free except bind).
- The **API** is the only writer of engine files, and only through the deploy
  pipeline.
- The **privileged helper** (firewall/service control) accepts a closed set of
  operations with typed arguments — no strings reach a shell (S6).
- **Secrets** live in `/etc/xoxproxy/secrets.env` (0600, root): session key,
  mgmt secret. The DB stores hashes only; plaintext passwords exist
  transiently at creation/rotation and in the one-time API response.

---

## 6. Failure Boundaries (per GUIDE failure scenarios)

| Failure | Data plane | Control plane | Detection |
|---|---|---|---|
| DB unavailable/corrupted | unaffected | API degrades (read-only where possible), health ready=false | db error metrics + readiness |
| Engine crash | traffic stops | alerts, systemd restarts from last-good files | liveness probe, restart counter |
| Invalid config generated | unaffected (old config retained) | deploy aborts, audit + alert | pipeline validation stage |
| Reload fails | rollback to last-known-good | audit + alert | health verify stage |
| Analytics dies | unaffected | SSE shows stale, error metric | ingestor heartbeat metric |
| Disk 90%/100% | unaffected until log write fails | alerts; shed analytics detail; refuse deploys at 100% | disk job |
| TLS renewal fails | unaffected | dashboard banner + alert | cert-expiry job (T-14d) |
| Server reboot | systemd orders: files exist → engine first → control plane | — | boot health check |
| Quota exhausted / user expired | user denied (users-file reload) | audit + dashboard status | reconciliation job |

Liveness (`/health/live`) = process serving. Readiness (`/health/ready`) =
DB reachable + config deployable. **Engine health is separate**
(`/api/v1/proxy/status`) and never marks the control plane unready, and vice
versa.

---

## 7. Database Schema (summary — full DDL is Phase 3)

```
users              id, server_id (default 'local'), username (unique), status,
                   allowed_protocols, download_limit_bps, upload_limit_bps,
                   max_connections, quota_bytes_daily, quota_bytes_monthly,
                   expires_at, version (optimistic lock), created_at,
                   updated_at, last_seen_at
credentials        id, user_id, engine_hash (CR:...), api_hash (argon2id),
                   status, rotated_at, created_at
usage_periods      user_id, period_start, granularity (hour/day/month),
                   bytes_in, bytes_out, connections   -- uint64, upsert
audit_logs         ts, actor, action, target, request_id, source_ip, result
admin_accounts     id, username, argon2id_hash, failed_attempts, locked_until
admin_sessions     id, account_id, token_hash, created_at, expires_at, ip
configuration_versions  revision, generated_at, generated_by, reason,
                   validation_status, deployment_status, checksum
settings           key, value (JSON)  -- ports, tls mode, retention, privacy
```

Migrations are versioned, forward-only, run by `xoxproxy server` at start and
by the installer; schema avoids SQLite-only types where PostgreSQL differs.

---

## 8. Deployment Model

### Install (one command, idempotent)

```
curl -fsSL https://get.xoxproxy.dev/install.sh | sudo bash --
  [--domain proxy.example.com] [--email admin@example.com]
  [--http-port 3128] [--socks5-port 1080] [--dashboard-port 8443]
  [--enable-tls|--disable-tls] [--admin-user admin] [--non-interactive]
  [--dry-run]
```

Phases: preflight (OS, arch amd64/arm64, RAM, disk, systemd, ports, existing
installation, DNS if domain) → deps → system user + dirs → secrets → engine
install → control plane install → DB init → firewall → Caddy (if domain) →
systemd enable/start (engine before control plane) → health verify → print
access info (URL, one-time admin password setup). `--dry-run` reports
everything it would do and everything that would fail.

### Files

```
/usr/bin/xoxproxy            control plane + CLI
/usr/bin/3proxy              engine (pinned version, checksum-verified)
/etc/xoxproxy/               config.toml, secrets.env (0600)
/etc/xoxproxy/engine/        generated 3proxy.cfg, users.txt (0600)
/var/lib/xoxproxy/           xoxproxy.db, counters, config history
/var/log/xoxproxy/           engine.log, app.log (rotated)
```

### Resource envelope

Target: comfortable on 1 vCPU / 1 GB. Engine < 10 MB RSS typical; control
plane bounded (< 128 MB RSS default via systemd `MemoryMax`); dashboard is
static assets; SQLite in WAL with small page cache.

---

## 9. Multi-VPS Evolution (design seams, not features)

The v1 appliance is node-complete: it owns its users, its engine, and its
analytics. The seams that make a central controller possible later:

1. **`DesiredState` document** — the deploy pipeline already consumes a
   serializable, versioned desired-state snapshot rather than issuing ad-hoc
   engine commands. A future agent receives exactly this document over a
   control channel.
2. **`ProxyEngine` interface** — the agent wraps the same interface; nothing
   else changes.
3. **`server_id` in the schema** — multi-node users/policies shard cleanly;
  v1 always writes `'local'`.
4. **No assumption of a shared filesystem, shared DB, or central relay** —
   proxy traffic never crosses the control channel.

What v1 deliberately does not build: agent protocol, central UI, node
registry, distributed metrics. Those arrive with the second node, not before.
