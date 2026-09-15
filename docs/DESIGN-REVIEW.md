# Design Review — xoxproxy

> Phase 1 deliverable. This document records the risks and deliberate tradeoffs
> identified **before** implementation, per the design review requirement in
> GUIDE.md. The architecture that follows from these decisions is in
> [ARCHITECTURE.md](ARCHITECTURE.md); adversary analysis is in
> [THREAT-MODEL.md](THREAT-MODEL.md).

Locked-in decisions:

| Decision | Choice |
|---|---|
| Proxy engine (first provider) | **3proxy** |
| Packaging | **Single Go binary** (`xoxproxy`) with embedded dashboard |
| Product name | **xoxproxy** (`/etc/xoxproxy`, `xoxproxy.service`, `xoxproxy-engine.service`) |

---

## 1. Top 10 Architectural Risks

### R1 — 3proxy reload semantics may not cover all desired-state changes

> **Status: RESOLVED (Phase 4 spike).** Verified from source — see
> [SPIKE-3PROXY.md](SPIKE-3PROXY.md). Summary: reload is triggered by
> **SIGUSR1** (SIGHUP kills the daemon); a reload re-reads the entire
> config, restarts listeners (≤1 s overlap), keeps established
> connections alive but re-authenticates them against the new config
> (force semantics = immediate revocation of deleted users' live
> connections). Users, ACLs, ports, and counters all apply on reload.
> A parse error stops the proxy (fail-closed, no rollback) — confirming
> the need for generate-only-validated-configs and a redeploy-previous
> rollback path.

3proxy re-reads parts of its configuration (notably the user list) when
triggered via its management interface, but the exact scope of what a reload
applies versus what requires a process restart is engine-version-dependent and
must be treated as **unverified until the Phase 4 spike**.

**Impact:** if only the users file can be hot-reloaded, then port, listener, or
ACL changes would require an engine restart, which drops active connections.

**Mitigation:**
- The `ProxyEngine` interface exposes `Reload` and `Restart` as distinct
  operations; the deployment pipeline picks the least disruptive one that is
  sufficient for the diff being applied (users-only change → reload; listener
  change → restart with warning).
- Restart is never silent: the API response and audit log record whether
  connections were dropped.
- If the spike proves reload scope inadequate, fallback is scheduled restart
  windows — documented, not hidden.

### R2 — No reliable offline config validator for 3proxy

3proxy has no `--check-config` mode; the only true validation is starting the
process. A config that parses but fails at runtime (bad directive, port
conflict) would take the data plane down.

**Mitigation:**
- Structural validation in Go before writing anything: full AST-level checks we
  generate ourselves (since we are the ones generating the config, we can
  guarantee invariants) plus port-conflict checks against `ss`/`/proc/net`.
- The deployment pipeline (R1) already includes *start-then-health-check*; for
  restart-class changes the pipeline starts the new config on a **staging
  invocation** before swapping the live one (start 3proxy with the candidate
  config on a temporary high port / loopback-only listeners, confirm it boots
  and binds, then deploy). Details validated in the Phase 4 spike.
- Last-known-good config is always retained on disk and is what the engine is
  restarted from by systemd after a failed deploy.

### R3 — Traffic accounting gaps on crash

Byte counters live partly in 3proxy's process memory (and its persistent
counter file, if enabled). If the engine crashes, usage between the last
counter-file sync and the crash can be under-counted.

**Mitigation:**
- Enable 3proxy's persistent counters if the spike confirms their semantics;
  otherwise reconcile from the structured log (which we tail continuously) and
  accept a documented loss window (bounded by log flush frequency).
- Quotas are enforced with a safety margin (a user can exceed quota by at most
  one accounting interval, never by an unbounded amount, because the *engine*
  enforces `countin`/`countout` limits natively where confirmed — see R4).
- Accounting loss never blocks traffic; it only affects billing accuracy.

### R4 — 3proxy native quota semantics unverified

> **Status: RESOLVED (Phase 4 spike).** Verified from source — see
> [SPIKE-3PROXY.md](SPIKE-3PROXY.md). Summary: `countin` counts
> downloads, `countout` uploads, limit in MB, reset period per counter
> (H/D/W/M). Enforcement is immediate and fully in the data plane: new
> connections refused at auth, established connections killed the
> moment they exceed the remaining allowance. Counters persist to a
> binary `3CF` file (dumped every minute and on reload; record number
> must be stable — we use the user's DB row id). Reset boundaries are
> approximate (first dump after local midnight) — hence the
> control-plane ledger stays the source of truth for exact periods,
> with engine counters as the enforcement backstop, exactly the
> degradation-free variant of the mitigation below.

3proxy documents per-user traffic counters (`counter`/`countin`/`countout`)
that can deny a user after a byte threshold. Whether the reset periods and
persistence semantics match our monthly/daily quota model is **unverified**.

**Mitigation:**
- Phase 4 spike explicitly tests: native limits, reset semantics, persistence
  across restarts, interaction with the user file reload.
- The control plane maintains its **own** accounting as the source of truth for
  analytics and quota policy; engine-native limits are used as a hard
  enforcement backstop. If native limits don't fit the model, enforcement
  becomes: control-plane reconciliation job rewrites the users file (deny
  over-quota users) on a bounded interval. This is slower (over-quota traffic
  continues for up to one reconciliation interval) but architecturally sound —
  and it is the documented degradation mode either way.

### R5 — Control-plane/data-plane separation erosion

The biggest long-term risk is feature creep putting per-request logic (DB
lookups, API calls) into the proxy path, silently coupling the planes.

**Mitigation:**
- Structural: the engine talks to *nothing* but its config file, its users
  file, its log output, and its loopback management socket. There is no code
  path from engine request handling to the control plane.
- Process: any PR that adds an engine dependency on the control plane is
  rejected at review; the `ProxyEngine` interface is the only contract.
- The dashboard going down, the DB being corrupted, the API crashing — none of
  these can reach the engine because there is no channel by which they could.

### R6 — SQLite write contention

Single-writer database shared by API writes, analytics flushes, audit logging,
and reconciliation jobs. On a 1 vCPU VPS, a large analytics flush blocking an
admin write for seconds would feel like a hang.

**Mitigation:**
- WAL mode, `busy_timeout`, one writer goroutine per subsystem with bounded
  queues; analytics flushes are batched transactions (one write tx per flush,
  not one per event).
- Analytics degradation contract: if the analytics queue is full, counters are
  coalesced in memory (sums, not events) rather than blocking; the only loss
  from sustained overload is per-event granularity, never totals accuracy
  beyond the coalescing window.
- Repositories behind interfaces so PostgreSQL remains a drop-in path for
  multi-node evolution.

### R7 — Configuration deploy races

Two admins editing users simultaneously, or a reconciliation job firing during
a manual deploy, could generate from stale desired state or interleave
deployments.

**Mitigation:**
- Single-flight deployment: one in-flight deploy guarded by a mutex; queued
  deploys collapse into "deploy latest desired state" (idempotent — deploys
  always regenerate from current DB state, never from a diff).
- Optimistic locking on user rows (`version` column) for concurrent edits;
  last-writer-wins is rejected with a conflict error, not silent.

### R8 — IPv6 exposure mismatch

A firewall configured for IPv4 only leaves the engine's IPv6 listeners as an
open proxy on any IPv6-enabled VPS.

**Mitigation:**
- Generated engine config explicitly binds both families; firewall automation
  (nftables) always writes both `ip` and `ip6` family rules from the same
  policy structure.
- The health/audit job detects listeners or firewall state that exposes
  unauthenticated ports on either family and raises an admin alert.
- If IPv6 is deliberately disabled, the config disables the listeners, not
  just the firewall rules.

### R9 — Firewall automation on unknown existing state

VPS images arrive with ufw/iptables/docker rules/nftables in arbitrary states.
Naive rule injection can lock out SSH.

**Mitigation:**
- Preflight in installer: inventory existing rules; refuse (require `--force`)
  if a conflicting or unknown firewall manager is active (e.g. Docker's iptables
  chains).
- Never modify the SSH port rule without an explicit flag; always add an
  allow-SSH rule before any drop policy; verify our own session still works
  post-change (installer does a connectivity self-check before committing).
- Own rules are tagged with a dedicated nftables table (`inet xoxproxy`) so
  they are identifiable and removable without touching foreign rules.

### R10 — Multi-VPS evolution postponed too long

The guide requires that multi-node support not need a rewrite, but also forbids
premature distributed design.

**Mitigation:**
- Keep desired state serializable (a versioned `DesiredState` document), keep
  `ProxyEngine` free of UI/API concerns, keep node identity in the schema
  (`server_id` reserved, defaults to `local`), and keep every engine
  interaction expressible as: *here is a config bundle, deploy it, report
  status*. The future agent is then a transport wrapper around the same
  interface, not a redesign.

---

## 2. Top 10 Security Risks

### S1 — Accidental open proxy

The single worst outcome. Any bug in auth config generation, user-list
serialization, or engine defaults could expose an unauthenticated proxy to the
internet.

**Mitigation:**
- Generated config **fails closed**: the generator emits explicit `auth strong`
-style directives for every listener; if the users file is empty or the
generator errors, no listener is emitted at all.
- Startup validation: the engine's own process runs as a non-root user; the
  control plane verifies on boot and periodically (health job) that every
  public listener requires auth — by probing it, not by trusting the config
  file (connect attempt without credentials must fail).
- Anonymous access requires an explicit, audited, CLI-only
  `allow-anonymous` operation with a typed confirmation phrase — never a
  dashboard toggle.

### S2 — Credential storage in the engine's users file

3proxy authenticates against its own user file with a native hash format
(`CR:` — an unsalted MD5-based hash). This is weaker than bcrypt/argon2 and
incompatible with storing only bcrypt hashes.

**Tradeoff (explicit):** we store `CR:` hashes for engine auth (never
plaintext `CL:` unless a required feature proves otherwise) and additionally
store a bcrypt hash of the same password in the control-plane DB for
verification/API purposes. Consequences:
- Offline cracking of a leaked users file is feasible against weak passwords →
  generated passwords are 20+ chars from `crypto/rand`, making MD5's weakness
  immaterial in practice; manual weak passwords are rejected by policy.
- The two hash columns can drift on rotation → rotation always rewrites both in
  one transaction; the users file is regenerated, not edited.
- Documented in SECURITY.md; revisited if 3proxy gains a stronger format or we
  swap engines (engine replaceability exists partly for this).

### S3 — Installer: `curl | sudo bash` and supply chain

The classic installer pattern is arbitrary code execution if the download is
compromised.

**Mitigation:**
- Release artifacts published with SHA-256 checksums **and a signature**; the
  installer verifies both before executing anything (bootstrap downloads a
  small, auditable installer that then verifies the payload).
- Pinned dependency versions, SBOM + checksums per release, `go.sum`
  enforcement, Dependabot/renovate, `govulncheck` in CI.
- Installer is `set -euo pipefail`, POSIX sh, no `eval` of remote content,
  idempotent, transactional where possible (staging dir + atomic move).

### S4 — Admin authentication and session attacks

Brute force, session fixation, CSRF, cookie theft on IP-only HTTP deployments.

**Mitigation:**
- Argon2id admin password hashing; login rate limiting with per-IP and
  per-account backoff; generic failure messages; audit every attempt.
- Server-side sessions (DB-backed) with rotation on login; `HttpOnly`,
  `SameSite=Lax`, `Secure` cookies (with an explicit, warned exception only
  for deliberate HTTP-only IP deployments).
- CSRF: double-submit token + `SameSite` for state-changing routes; all
  mutations are POST/PATCH/DELETE with JSON bodies (no cookie-authenticated
  GET mutations).
- Session store behind an interface → future passkeys/TOTP without redesign.

### S5 — Engine management interface exposure

The loopback management socket that allows user reload (and potentially more)
must never be reachable externally or from the engine's own unprivileged
context in a way that escalates.

**Mitigation:**
- Management socket binds `127.0.0.1` only (config-generated, validated at
  deploy); firewall table blocks it from other interfaces by default; the
  control plane is the only writer of the management credentials.
- Management access is authenticated (3proxy's own mechanism) with a generated
  secret in `/etc/xoxproxy/secrets.env` (mode 0600, root-owned).

### S6 — Privilege and command-injection surface

Firewall and service management need elevated rights; the API must never
construct shell commands from user input.

**Mitigation:**
- `xoxproxy` (control plane) runs as its own unprivileged user. Privileged
  operations (nft, systemctl) go through a **narrow, fixed-argument** helper
  invoked via `exec.CommandContext` with argument arrays — never a shell — and
  sudoers rules pinning exact arguments; or via a dedicated root systemd
  service with a local unix-socket RPC of a fixed command vocabulary. (Exact
  mechanism chosen in Phase 2/9; the constraint — fixed vocabulary, no string
  interpolation — is non-negotiable.)
- Caddy binds 443 (needs the capability) so the dashboard backend never runs
  as root.

### S7 — Log-driven abuse handling and sensitive data in logs

Proxy logs contain destinations, usernames, client IPs; app logs could leak
secrets.

**Mitigation:**
- Structured JSON logging with a secret-redacting field allowlist; credential
  values are structurally never passed to loggers (not just filtered).
- Destination URLs logged in truncated/redacted form (scheme+host, not path or
  query) with a documented privacy mode; retention configurable; IP
  anonymization option (hashed client IPs) for analytics storage.
- Log rotation with size caps enforced by the control plane itself, not left
  to hope.

### S8 — API hardening

Internet-facing admin API.

**Mitigation:**
- Strict validation on every input (ports in range, no path parameters
  reaching filesystem paths, bounded bodies, timeouts on every handler);
  consistent structured error envelope with request IDs; no stack traces or
  filesystem paths in responses; pagination mandatory on list endpoints;
  rate limits on auth and mutation endpoints; security headers on all
  responses; audit on all privileged actions.

### S9 — Upgrades as an attack/failure vector

A compromised or corrupted upgrade package is arbitrary code execution; a
half-applied upgrade is an outage.

**Mitigation:**
- Upgrade flow: verify signature → backup (DB + config + secrets manifest) →
  stage → migrate → validate → switch → health check → auto-rollback to
  previous binary + config on failure. The engine binary and control plane
  upgrade independently; a control-plane upgrade never restarts the engine
  unnecessarily.

### S10 — Traffic/accounting integrity

Quota bypass by racing counter resets, or resource theft via unbounded
connections.

**Mitigation:**
- Integer-only byte counters (uint64); atomic upserts within the flush
  transaction; quota period boundaries computed in UTC with explicit period
  rows (no floating point, no "subtract and hope").
- Per-user and global connection caps, fd/memory limits in systemd units,
  idle timeouts on the engine; auth-failure thresholds trigger temporary
  firewall-level bans (bounded duration, audited, with unban mechanism).

---

## 3. Most Likely Operational Failures

Ranked by expected frequency × pain:

1. **Disk full from logs/analytics** — rotation + 90% disk alert + a hard
   enforcement mode (shed analytics detail, alert loudly) before 100%.
2. **TLS renewal failure** (domain moved, DNS changed, port 80 blocked) —
   cert-expiry monitoring with warning at T-14d, dashboard banner, documented
   recovery.
3. **Conntrack / fd exhaustion under load** — monitoring, sysctl guidance with
   justification, engine limits sized to fd budget.
4. **Admin locks themselves out** (firewall change) — installer self-check,
   console-access recovery runbook, `xoxproxy firewall reset` on localhost.
5. **Engine crash loop** (bad edge in generated config) — systemd
   `Restart=on-failure` with backoff, alert, last-known-good auto-restore
   after N failures.
6. **SQLite corruption** (power loss) — WAL + `PRAGMA integrity_check` job,
   documented restore from backup.
7. **Clock skew breaking quota resets / expiry** — NTP dependency documented;
   periods keyed to server UTC time.
8. **Port collision with user's existing services** — installer preflight
   checks listeners before configuring.
9. **Reboot ordering** — systemd `After=`/`Requires=` so the engine never
   starts before its config exists; config is on disk, not generated at boot.
10. **VPS IP change** — dashboard detects public IP drift, warns (TLS cert
    invalid, proxy endpoints stale).

---

## 4. Scalability Bottlenecks

- **SQLite single writer** — fine for a single node with batched writes;
  PostgreSQL path preserved for multi-node. Not a problem to fix now.
- **Log tailing throughput** — structured log parse rate; mitigate with binary
  log format choice in spike and coalescing counters. Sizing target: 10k
  events/s sustained on 1 vCPU without dashboard impact.
- **Per-connection state in the control plane** — the control plane tracks
  *connections only as aggregated counters*, never per-connection goroutines.
- **Dashboard time-series queries** — pre-aggregated period tables (hourly/
  daily rollups), never raw-event scans.
- **Config regeneration cost** — regenerate on change only; a full regen for
  10k users is sub-second; no caching layer needed.

Everything else (multi-node control channel, per-node agents, centralized
metrics) is explicitly **out of scope** for the first release.

---

## 5. Where the Design Intentionally Stays Simple

- **Single server, single admin.** The schema reserves `server_id` and
  role/actor columns, but there is no org/tenant machinery, no RBAC UI, no
  API keys in v1.
- **No Redis, no message queue, no OTel collector.** In-process bounded
  queues and Prometheus-format exposition are sufficient at this scale.
- **No high availability.** One VPS, systemd supervision, backups. HA is a
  multi-node problem and pretending otherwise adds failure modes.
- **File-based engine auth**, not LDAP/API-callback auth — one moving part,
  hot-reloadable, engine-native.
- **Cron-style in-process jobs**, not a job scheduler framework.
- **Dashboard reads analytics tables directly** via the API — no separate
  analytics service.

The guide is explicit: do not over-engineer the distributed system before the
appliance is correct.

---

## 6. Components That Must Be Replaceable

| Component | Interface | Why |
|---|---|---|
| Proxy engine | `ProxyEngine` (Install/Start/Stop/Reload/Restart/ValidateConfig/GenerateConfig/GetStatus/GetLogs) | Engine swap (3proxy → alternative) without touching domain logic; also the multi-node agent boundary |
| Database | Repository interfaces | SQLite → PostgreSQL |
| Reverse proxy/TLS | Caddy (external binary, config-managed) | Could be nginx/traefik; also optional (IP-only HTTP mode has none) |
| Session store | `SessionStore` | In-DB today; Redis/external later |
| Metrics sink | `Metrics` interface | Prometheus exposition today; OTel export later |
| Analytics ingestion | `TrafficIngestor` | Log-tail today; counters file or agent push later |

## 7. Components That Must Never Be Coupled

1. **Engine request path ↔ anything.** The engine handles traffic using only
   files written before the connection existed.
2. **Config generation ↔ engine syntax in domain code.** Domain model emits a
   semantic `DesiredState`; only the provider translates to 3proxy syntax.
3. **CLI ↔ separate business logic.** CLI and HTTP API share one service
   layer; no duplicated rules.
4. **Analytics correctness ↔ traffic availability.** Analytics may degrade to
   coarser data; traffic never waits for analytics.
5. **Dashboard ↔ engine control.** The dashboard can only reach the engine
   through the same audited service layer the API uses — no direct management-
   socket access from frontend code.
