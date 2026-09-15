# Security Testing Plan & Acceptance Matrix — xoxproxy

> **This is a release gate, not a checklist.** Security is release-blocking.
> A feature is not accepted because the UI prevents an attack — every
> control below is enforced by the backend/data layer and verified by an
> automated test that sends hostile requests directly to the HTTP layer or
> the data layer.

## How this document is used

- Every category has: **threat model, preventive controls, automated
  tests (with file references), attack cases, expected behavior, and
  evidence of server-side enforcement.**
- Security tests run in CI as part of `go test ./...` and explicitly as
  `make test-security` (`go test -run TestSecurity ./...`). Test names are
  prefixed `TestSecurity*` and live next to the code they protect.
- Any confirmed vulnerability in a gate category is **release-blocking**
  until fixed **and** covered by a regression test in this suite, so it
  cannot silently return.
- Categories whose attack surface does not exist yet are marked *not yet
  applicable* with the phase that introduces the surface and therefore the
  tests. They are not skipped: they are scheduled, and the phase is not
  complete without them.

## Release-gate categories

A confirmed instance of any of these is a release-blocking vulnerability:
authentication bypass, authorization bypass / IDOR, SQL injection, command
injection, SSRF to protected/internal resources, stored XSS with meaningful
impact, path traversal allowing unauthorized file access.

---

## 1. SQL Injection (SQLi)

| Aspect | Detail |
|---|---|
| Threat model | Attacker sends SQL fragments in login fields, query parameters (limit, before_id, action), or future user/settings fields, aiming to bypass auth, dump hashes, or destroy tables. Second-order: payloads stored in the DB (e.g. usernames) later concatenated into queries. |
| Preventive controls | 100% parameterized queries (`?` placeholders, never string interpolation) enforced by the repository layer; query values never concatenated; strict input validation (numeric params parsed as integers, exact-match allowlists for enum-like filters); SQLite driver rejects multi-statement execution by default. |
| Automated tests | `internal/api/security_test.go`: `TestSecuritySQLiLoginFields`, `TestSecuritySQLiQueryParameters` (first-order + database-intact second-order checks). Store layer exercises parameterization via `internal/store/sqlite/store_test.go`. |
| Attack cases | `' OR '1'='1`, `'; DROP TABLE admin_sessions; --`, `UNION SELECT password_hash ...`, `ATTACH DATABASE`, unicode/numeric edge payloads in `limit`, `action` filters. |
| Expected behavior | 401 (login) / 400 or empty result (queries); identical error envelopes as any other bad input; database remains fully functional; no SQL text or driver errors in responses. |
| Server-side evidence | Tests send crafted HTTP requests with no UI; they assert the DB still authenticates the real account afterwards (intact tables = injections executed as literal strings). |

## 2. Cross-Site Scripting (XSS)

| Aspect | Detail |
|---|---|
| Threat model | Attacker injects HTML/JS via any echoed or stored field (login username, audit actor/target/detail, future user fields), aiming for admin-session theft. |
| Preventive controls | The API emits JSON only via `encoding/json` (contextual encoding by construction); error messages are fixed strings — user input is never reflected; `Content-Type: application/json` + `X-Content-Type-Options: nosniff` prevent browser sniffing; CSP `default-src 'none'` on API responses; dashboard (Phase 8) will use React's default escaping with an explicit no-`dangerouslySetInnerHTML` rule and a CSP. |
| Automated tests | `TestSecurityXSSNotReflected` (reflected); `users_security_test.go`: `TestSecurityStoredXSSUserFields` (stored — script payloads in username/protocol/status fields are rejected at validation, never reflected, never stored, never in the audit trail; a legitimate username round-trips unchanged as a JSON string). |
| Attack cases | `<script>alert(1)</script>`, `<img onerror=...>`, JS-expression payloads, `</textarea>` breakout attempts. |
| Expected behavior | Payload appears nowhere in response bodies (fixed envelopes only); hostile values in user fields are **not admitted at all** — the username charset policy (§6) rejects markup by construction, so there is nothing to sanitize downstream; legitimate values re-serialize as JSON strings; nosniff + CSP present on every response. |
| Server-side evidence | Tests assert absence of payload in raw response bytes and presence of headers — independent of any frontend behavior. |

## 3. Cross-Site Request Forgery (CSRF)

| Aspect | Detail |
|---|---|
| Threat model | A logged-in admin's browser is tricked by a hostile page into issuing state-changing requests (logout, password change, future user mutations). |
| Preventive controls | Session cookie is `SameSite=Lax` + `HttpOnly` (+ `Secure` under TLS); every state-changing route is POST/PATCH/DELETE only; all mutations require the `X-CSRF-Token` header matching the **server-stored per-session** token (constant-time compare) — stronger than double-submit since it cannot be planted by a subdomain; `Content-Type: application/json` enforced, which a cross-site form cannot set without a CORS preflight the API never grants. |
| Automated tests | `server_test.go`: `TestCSRFEnforced` (missing/forged token → 403); `security_test.go`: `TestSecurityNoGetMutations` (no GET mutations exist), content-type rejection in `TestLoginFailuresAreUniform` (415 for form posts). |
| Attack cases | Cross-site form post, `fetch` with `text/plain` body, missing header, forged header value, replay of another session's token. |
| Expected behavior | 403 `CSRF_TOKEN_INVALID` for any mutation without an exact, session-matching token; 415 for non-JSON content types. |
| Server-side evidence | Middleware-level enforcement before handlers run; tests hit the raw router. |

## 4. Server-Side Request Forgery (SSRF)

| Aspect | Detail |
|---|---|
| Threat model | Not yet applicable — no endpoint fetches attacker-supplied URLs. Future surfaces: update checker, public-IP detection, DNS/TLS verification (Phase 9), webhook/alerting. |
| Preventive controls (planned, enforced at introduction) | Scheme/host allowlists; resolved-IP rejection of loopback, RFC1918, link-local (169.254.169.254 metadata), and the control plane's own listener; no redirects to non-allowlisted hosts; timeouts and response size caps. |
| Automated tests | Scheduled for Phase 9: URL validation unit tests + attack cases (`http://127.0.0.1:8080`, `http://[::1]/`, `http://169.254.169.254/`, DNS-rebinding simulation via custom resolver, redirect chains). |
| Expected behavior | Any URL resolving to internal/private space is rejected before any connection attempt. |
| Server-side evidence | URL parsing and IP policy live in a dedicated server-side validator package with its own tests; the HTTP handlers cannot bypass it (type-level: handlers accept parsed, validated URL values). |

## 5. Insecure Direct Object Reference (IDOR)

| Aspect | Detail |
|---|---|
| Threat model | The proxy-user object routes (Phase 5) and the deploy-pipeline routes (Phase 6: `/api/v1/config-versions`, `/api/v1/engine/status`, `POST /api/v1/deploy`) expose control-plane objects. An attacker without an admin session — or with a session but missing the CSRF token — attempts to read, mutate, or enumerate objects, or to reach them via crafted identifiers or query values (guessable ids, SQL fragments, traversal shapes, overflow values). Future surface: API keys and multi-principal access, where object ownership itself must be checked. |
| Preventive controls | Every user route is wrapped in `withSession`: the session cookie is verified server-side against the DB (hashed token) before any handler runs — there is no path to a handler without an authenticated principal. Mutations additionally require the session-matching CSRF header (§3). Object ids are parsed as strict positive integers (`parseUserID`) — crafted ids never reach the storage layer. v1 has a single administrator role with no lower-privileged principal, so *authorization* is currently all-or-nothing; object-ownership columns (`server_id`) already exist in the schema for future enforcement in SQL WHERE clauses, and ids are never treated as security tokens (existence is not a secret; a missing object is a plain 404). |
| Automated tests | `users_security_test.go`: `TestSecurityIDORUserRoutes` — for **every** user route: 4 unauthenticated/forged-session variants (no cookie, empty cookie, unknown token, spoofed `Authorization`/CSRF headers) must get 401 with no object data; valid session without CSRF on every mutation route must get 403; 11 crafted ids (`999`, `0`, `-1`, `abc`, `1;DROP`, `1.5`, `1e3`, `..%2F2`, `%31`, overflow) across every `{id}` route must yield 400/404 with no object data, no SQL text, no 500; a logged-out session grants nothing; an authenticated control request still succeeds (denials are authorization, not breakage). `deploy_handlers_test.go`: `TestSecurityDeployRoutes` — the same discipline for the Phase 6 routes: forged/unauthenticated reads 401 with no version data, `POST /api/v1/deploy` 401 unauthenticated / 403 without CSRF, crafted `limit` values 400 with no internals. |
| Attack cases | See the test matrix above; plus session-replay after logout. |
| Expected behavior | 401 before handler logic for every forged request; 403 for CSRF-less mutations; 400/404 for crafted ids; never the object, never internals, never a 500. |
| Server-side evidence | All assertions drive the raw router with crafted HTTP requests — no UI. The session check is middleware, so a handler cannot forget it; the id parse is the first statement of every `{id}` handler. |

When API keys / multi-principal access arrive, this suite gains an authenticated-but-unauthorized matrix (principal A touching principal B's objects) asserting 403/404 at the service layer.

## 6. Command Injection / OS Command Execution

| Aspect | Detail |
|---|---|
| Threat model | The control plane manages the proxy engine, so process control and config generation exist (Phase 4). Two concrete injection surfaces: (a) **engine config injection** — the rendered 3proxy config is the data plane's program; a hostile username, hash, or setting could smuggle directives (`allow *`, `auth none`, a second `users` line with a cleartext `CL:` password); (b) **process signaling** — reload must signal the engine PID, and a wrong/stale PID file could terminate an unrelated process. No shell is ever invoked; `exec`-style surfaces remain future work (firewall management, Phase 9). |
| Preventive controls | Config injection: usernames constrained to `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` (no whitespace, `:`, `"`, newline — the tokens 3proxy's parser splits on), enforced **at render time**, not just at the API; engine hashes must match the exact `$3$salt$22-char-digest` shape; users entries are double-quoted (`$` is an include directive otherwise); settings paths reject `..` components and control bytes; nameservers validated as IPs. Quotas floor to whole MiB so the rendered limit never exceeds the configured one. Signaling: PID identity verified against `/proc/<pid>/cmdline` (basename must be `3proxy`) before any signal is sent. The `noforce` directive (which would let revoked users keep live connections) is never emitted, verified by test. |
| Automated tests | `internal/engine/threeproxy/config_test.go`: `TestSecurityConfigInjectionViaUsername` (14 payload shapes: newline directive injection, `:CL:backdoor`, whitespace/quote/tab escapes, comment smuggling, NUL/DEL, non-ASCII, length), `TestSecurityConfigInjectionViaHash` (10 shapes), `TestSecurityQuotaCannotExceedConfigured`, `TestRenderRecordNumberZeroRejected`, `TestRenderEmptyUsersIsNeverOpenProxy`; `logparse_test.go`: `TestSecurityLogInjectionNoMisattribution` (hostile log lines can never attribute traffic to a real user); `deploy_test.go`: `TestDeployRefusesToSignalForeignProcess`, `TestDeployRejectsInvalidStateBeforeTouchingDisk`. |
| Attack cases | Username `alice\nallow *`, `alice:CL:backdoor`, `alice" allow *`, tab-splitting, `-alice` (flag position); hash payloads with embedded quotes/colons/newlines; nameserver `1.1.1.1\nallow *`; config path `/etc/xoxproxy/../../tmp/x`; PID file pointing at nginx. |
| Expected behavior | `Render`/`Deploy` reject every hostile value before anything reaches disk; an unidentifiable PID is never signaled (config stays installed for the next engine start); empty state renders `auth strong` + no users — never an open proxy. |
| Server-side evidence | Tests construct hostile `engine.State` values directly and call the render/deploy layer — no API or UI in the path. The username policy is re-checked inside `Render`, so even a compromised caller above it cannot inject. |

**Not yet applicable within this category:** OS command execution via `exec` (no process spawning exists; firewall management in Phase 9 will use fixed-argv `exec.CommandContext` with a closed enum vocabulary, audited, and covered by fuzz tests at introduction). |

## 7. Path Traversal

| Aspect | Detail |
|---|---|
| Threat model | Two surfaces: (a) **engine file writes** (Phase 4) — the deployer writes the config, counter, and log paths under fixed `/etc`, `/var` roots; a crafted settings path could write outside them; (b) client-supplied file paths — not yet applicable; future surfaces: log viewing and config history (Phase 6-8). |
| Preventive controls | Deployer settings paths must be absolute, contain no `..` component (checked per path separator, both `/` and `\`), and contain no control bytes — enforced in `Settings.Validate`, re-checked in `Render` before any write; the deployer writes via a temp file in the **same directory** + atomic rename, so a partial write can never land at a traversal target; PID identity check prevents acting on foreign processes' files. |
| Automated tests | `config_test.go`: `TestRenderRejectsBadSettings` (`config path traversal` case `/etc/xoxproxy/../../tmp/x`, relative paths, control-byte nameserver payloads). Log endpoints and config history get the scheduled suite (`../` sequences, absolute paths, symlink escape, URL-encoded traversal, NUL bytes) when the surface is introduced. |
| Expected behavior | Requests can only ever reference the fixed, allowlisted file set. |
| Server-side evidence | Traversal payloads are rejected at the render layer — below the API — verified by direct unit tests with no HTTP in the path. |

## 8. Authentication Bypass

| Aspect | Detail |
|---|---|
| Threat model | Attacker seeks admin access via forged/manipulated cookies, header spoofing, session fixation, brute force, timing-based account enumeration, or lockout bypass. |
| Preventive controls | Server-side DB-backed sessions; only SHA-256 **hashes** of tokens stored; argon2id password hashing; uniform 401 for unknown-user/wrong-password/locked (no oracle); constant-time comparisons; timing-equalized unknown-user path; per-account lockout (5 failures / 15 min) + per-IP throttle (20 failures / 15 min); idle (2h) and absolute (7d) session expiry; password change revokes all other sessions; login rate limiting at HTTP layer; `clientIP` trusts XFF only from loopback (unspoofable throttle). |
| Automated tests | `security_test.go`: `TestSecurityAuthBypass` (crafted cookies, header spoofing), `TestSecuritySessionFixation`; `auth/service_test.go`: lockout, IP throttle, uniform errors, session expiry, password-change revocation; `server_test.go`: `TestLoginFailuresAreUniform` (byte-level identity modulo request ID). |
| Attack cases | Empty/garbage/foreign-name cookies; `Authorization`/CSRF headers as session substitutes; attacker-chosen session token surviving victim login; brute force to lockout; login after lockout expiry (recovery works). |
| Expected behavior | 401 for every unauthenticated crafted request; lockout engages; no account-existence oracle; sessions are server-minted only. |
| Server-side evidence | All tests drive the HTTP layer or service layer directly with crafted inputs; UI never participates. |

---

## Regression-test policy

1. Every fixed vulnerability gets a `TestSecurity*` regression test in the
   same package as the fix, referencing the fix in a comment.
2. The test name is added to the relevant category section above.
3. CI runs the full suite on every push and pull request
   (`.github/workflows/ci.yml`); `make test-security` runs only the
   security suite for fast local iteration.
4. A PR that removes or weakens a security test without a documented
   threat-model justification in SECURITY-TESTING.md is rejected.

## Current status (Phase 6)

| Category | Surface exists | Attack suite |
|---|---|---|
| SQLi | Yes | ✅ enforced + tested |
| XSS (reflected) | Yes | ✅ enforced + tested |
| XSS (stored) | Yes (user fields, Phase 5) | ✅ enforced + tested (payloads rejected at validation; never stored, reflected, or audited) |
| CSRF | Yes | ✅ enforced + tested |
| Auth bypass | Yes | ✅ enforced + tested |
| IDOR | Yes (user + deploy routes, Phases 5-6) | ✅ enforced + tested (route matrices + crafted ids/values); multi-principal matrix scheduled with API keys |
| Command/config injection | Yes (engine config, Phase 4) | ✅ enforced + tested (config injection, PID signaling); exec vocabulary suite scheduled Phase 9 (firewall) |
| Path traversal | Yes (engine file paths, Phase 4) | ✅ enforced + tested (settings traversal); log-viewing suite scheduled Phase 6-8 |
| SSRF | No (Phase 9) | scheduled |

Additionally enforced + tested in Phase 5 (not a gate category but a GUIDE invariant): **credential exposure** — `TestSecurityCredentialsNeverExposed` proves hashes and plaintext never appear in ordinary responses (the password is returned exactly once, in the create/rotate response), and `TestSecurityUserMutationAuditTrail` / `TestAuditTrailContainsNoSecrets` prove the audit trail contains no credential material.

Phase 6 extends the same invariant to the deploy pipeline: the rendered engine config contains `$3$` verifiers and is **never** persisted in the control-plane database or returned by any endpoint — `configuration_versions` stores only the SHA-256 checksum (asserted by `TestDeployEndpointsFunctional`), and `TestDeployOutcomeRecording` proves every generation, including failed and rolled-back ones, is recorded append-only with its outcome. Single-flight serialization and trigger coalescing (GUIDE: "do not allow two simultaneous configuration deployments to race") are regression-tested by `TestSingleFlightSerialization` and `TestTriggerCoalescesWhileDeployRunning` in `internal/deploy`.
