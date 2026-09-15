# Threat Model — xoxproxy

> Phase 1 deliverable. Companion to [ARCHITECTURE.md](ARCHITECTURE.md) and
> [DESIGN-REVIEW.md](DESIGN-REVIEW.md) (S-numbered items there map to the
> mitigations below).

## 1. Assets

| Asset | Impact if compromised |
|---|---|
| Proxy credentials (users.txt, DB hashes) | Unauthorized proxy use; bandwidth/quota theft; attribution of abuse to victim user |
| Admin session / admin account | Full control: create users, disable auth, open firewall, exfiltrate logs |
| Session secret, engine mgmt secret | Session forgery; unauthorized engine reload |
| TLS private keys | Dashboard impersonation, MITM of admin traffic |
| Traffic logs / analytics (client IPs, destinations, usernames) | Privacy breach of every proxy user |
| The VPS itself | Pivot for attacks; abuse infrastructure in the owner's name |
| Availability of the proxy service | DoS of the operator's business |

## 2. Adversaries

1. **Opportunist scanners** — find an open proxy and abuse it (the default
   threat; huge volume, low skill).
2. **Credential attackers** — brute-force proxy auth or admin login.
3. **A legitimate-but-abusive proxy user** — tries to exceed quotas,
   evade connection limits, resell access.
4. **Targeted attacker on the dashboard** — exploits the internet-facing
   admin API (injection, CSRF, session theft, SSRF via log endpoints).
5. **Supply-chain attacker** — compromises a release, dependency, or the
   installer download path.
6. **Local attacker / compromised co-tenant process** — reads secrets, talks
   to the loopback mgmt socket.

Not in scope: global passive adversaries, VPS provider compromise, endpoint
compromise of the admin's browser (mitigated where practical, not solvable).

## 3. Attack Surface Inventory

| Surface | Exposure | Primary defenses |
|---|---|---|
| 3proxy listeners (HTTP :3128, SOCKS5 :1080) | Internet, unauthenticated traffic | mandatory auth (fail-closed generation), rate/ban on failures, quotas, conn caps, connection-forensics logging |
| Dashboard/API (via Caddy TLS or direct) | Internet, unauthenticated traffic | sessions, CSRF, rate limits, argon2id, validation, error hygiene |
| `/metrics` | localhost only (firewall + bind) | not exposed publicly by default |
| Engine mgmt socket | 127.0.0.1, secret-authed | loopback bind enforced + validated, secret 0600 |
| Privileged helper (firewall/service ops) | local unix socket, xoxproxy user | fixed command vocabulary, no shell, sudoers pinning |
| Install/upgrade path | network download as root | signature + checksum verification, staged install |
| Proxy logs | local files, API-read | truncation of destinations, retention config, IP hashing option, no credentials ever |

## 4. STRIDE Summary

### Spoofing
- Proxy user spoofing → engine auth with hashed credentials, long generated
  passwords, rotation, immediate disable via users-file reload (S1, S2).
- Admin spoofing → server-side sessions, cookie flags, rotation on login,
  generic login errors, throttling + temporary lockout (S4).
- Release spoofing → signed artifacts, verifier refuses unsigned (S3, S9).

### Tampering
- Engine config tampering (local write or race) → atomic deploys, checksums
  in `configuration_versions`, boot-time + periodic config integrity
  verification, last-known-good restore (R2, R7).
- Quota counter tampering/races → integer counters, transactional upserts,
  engine-side backstops (R3, R4, S10).
- Firewall tampering → owned nft table with tagged rules, drift detection
  job (R8, R9).

### Repudiation
- Audit log with actor, action, target, request ID, source IP, result for
  every privileged operation; append-only table; credentials never in audit
  records.

### Information disclosure
- Credentials: never in logs/metrics/audit/errors/URLs; one-time display on
  create/rotate; structurally excluded from logger fields (S7).
- Destinations/client IPs: truncated logging, configurable retention,
  optional hashing; dashboards don't expose raw destinations to non-admin
  (v1: admin-only anyway).
- Error responses: request-ID envelope only; no paths, stack traces, or SQL.

### Denial of service
- Connection/fd exhaustion → per-user and global caps, idle timeouts,
  systemd resource limits, fd sizing (Resource Protection).
- Auth brute force → per-IP and per-account throttling, temporary
  firewall-level bans with audit + expiry (S10).
- Disk exhaustion → rotation, quotas on log size, 90% alerting, shed-to-
  survive analytics (Operational Failures #1).
- Control-plane DoS must not affect the data plane — guaranteed by the
  no-channel architecture (R5).

### Elevation of privilege
- Admin → root: only via the privileged helper's fixed vocabulary; no
  arbitrary command endpoints exist by design (S6).
- Engine (unprivileged user) → control plane: separate users, engine runs
  with hardened unit, cannot read secrets.env (root 0600) or the DB.
- CSRF/session → SameSite + double-submit tokens + no GET mutations.
- Injection classes: no shell interpolation anywhere (exec arrays only);
  parameterized SQL only; template-escaped dashboard; path-traversal-proof
  log reading (fixed directory, sanitized identifiers, no raw path params).

## 5. High-Severity Scenarios (must-pass test cases)

These become e2e security tests in Phase 11 — the build is not done until
each passes:

1. Fresh install, port-scan all exposed ports from outside: no unauthenticated
   proxy path on IPv4 **or** IPv6.
2. Connect to HTTP proxy with wrong credentials × N → blocked with backoff,
  then firewall-banned for a bounded period; audit entries present.
3. Create user, delete users file entry manually, wait for reconciliation →
   file restored from desired state.
4. Corrupt generated config via the API (malformed input attempts) → deploy
   refused, old config intact, engine never restarted.
5. Steal a session cookie from an HTTP-only deployment → documented risk
   banner shown at install; cookie flagged Secure whenever TLS is on.
6. Read `/var/log/xoxproxy/*.log`, DB dump, `/metrics`, audit export → grep
   for known plaintext passwords → zero hits.
7. Kill the control plane mid-deploy → engine still serving; on restart,
   deploy either completed atomically or rolled back — never half-applied.
8. Reboot the VPS → engine up before control plane, all users still enforced.
9. Feed oversized/garbage bodies to every API route → 4xx, no CPU spike, no
   log flood (bounded).
10. Run upgrade with a tampered binary → signature check refuses, old
    installation untouched.
