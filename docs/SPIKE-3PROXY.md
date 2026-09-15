# Spike: 3proxy reload and quota semantics (Phase 4)

Resolves **R1** (reload semantics) and **R4** (quota semantics) from
[DESIGN-REVIEW.md](DESIGN-REVIEW.md), and fixes the engine credential
format. Every claim below was verified by reading the 3proxy 0.9 source
(`src/3proxy.c`, `src/conf.c`, `src/proxymain.c`, `src/sockmap.c`,
`src/auth.c`, `src/limiter.c`, `src/3proxy_crypt.c`) and, where possible,
by executing the real code. Line references are to the master branch at
the time of writing (September 2026).

## 1. Reload (R1) — verified findings

### 1.1 The reload signal is SIGUSR1. SIGHUP kills the daemon.

`3proxy.c` installs exactly four signal handlers (no SIGHUP handler):

```c
signal(SIGCONT, mysigpause);   // pause / resume
signal(SIGTERM, mysigterm);    // exit
signal(SIGUSR1, mysigusr1);    // conf.needreload = 1
signal(SIGPIPE, SIG_IGN);
```

**SIGHUP is unhandled → default action = terminate.** Sending SIGHUP to
3proxy (the conventional reload signal) kills the proxy. The control
plane MUST send SIGUSR1, obtained from the PID written by the `pidfile`
directive. This is a hard, verified fact — deployment code that uses
SIGHUP would cause an outage on every config push.

Alternative trigger: `monitor <file>` re-reads config within one minute
of a watched file's mtime/size change. Too slow and indirect for our
pipeline; we use SIGUSR1.

### 1.2 What reload does

`mysigusr1` sets `conf.needreload`; the main loop (`cyclestep`, tick
≈ 1 s) calls `reload()` under `config_mutex`:

1. `conf.paused++`
2. `freeconf(&conf)` — swaps users, ACLs, bandlimits, traffic counters,
   log configuration. **Before freeing counters it calls
   `dumpcounters()`, so persisted counters survive the reload.**
3. `conf.paused++` (again — so `conf.paused` now differs from the value
   every running listener recorded at startup)
4. Re-reads the config file; `conf.version++`

### 1.3 Listener lifecycle across reload

Every service thread keeps `srv.paused` (its copy of `conf.paused` at
startup). The accept loop breaks when `conf.paused != srv.paused`, so
**all old listeners exit within ≈ 1 s (their poll timeout) and close
their sockets**; listeners for the re-parsed config are started during
`readconfig`. On Linux both old and new sockets set `SO_REUSEADDR` +
`SO_REUSEPORT`, so the new listener can bind while the old drains —
there is a sub-second overlap window where the kernel load-balances
between the two, both serving the *new* ACLs (ACLs are read from the
global `conf` at auth time, not from the thread's startup copy).

Consequences for xoxproxy:

- **Port changes and service additions/removals apply on reload** — no
  restart needed (contrary to what the Windows-oriented howto text says;
  on Unix, reload re-reads everything).
- Connections accepted during the overlap window are served correctly.

### 1.4 Established connections survive reload

The per-connection data pump (`sockmap.c`) checks on every iteration:

```c
if(param->version < conf.version){
    if(!param->srv->noforce && (res = (*param->srv->authfunc)(param)) && res != 2) RETURN(res);
    param->paused = conf.paused;
    param->version = conf.version;
}
```

After a reload, every established connection **re-authenticates against
the new config** at its next I/O step. A connection whose user was
deleted, disabled, or quota-exhausted is closed (force semantics). With
`noforce` the re-check is skipped — we do NOT use `noforce`; force is
the behavior the platform requires (user revocation must kill live
connections). This directly satisfies the "revocation is immediate"
requirement: **delete user → push config → SIGUSR1 → live connections of
that user drop at their next I/O.**

### 1.5 Reload failure mode

If the re-read config file has a parse error, `reload()` frees the
(partially built) new config — users/ACLs end up empty — and the old
listeners still exit (they already saw `conf.paused` change). Result:
**the proxy stops accepting connections entirely** (fail-closed, but
fail-stopped). There is no automatic rollback.

Implication (confirms R2): xoxproxy MUST validate generated configs
before deploying them. Our mitigation is structural: the generator is
the only author of the config, it emits from validated internal state,
and it rejects any input that cannot be rendered safely (§3). The
deploy pipeline additionally keeps the previous config and re-deploys it
if post-reload health checks fail (Phase 6 wires the checks).

## 2. Quotas (R4) — verified findings

### 2.1 Directive syntax and units

```
countin  <number> <type> <limit-MB> <userlist> ...
countout <number> <type> <limit-MB> <userlist> ...
countall <number> <type> <limit-MB> <userlist> ...
counter <counter-file> [<type> <report-path>]
```

From `conf.c` (`h_acl` COUNTIN case): `traflim64 = limit * 1024 * 1024`
— **the limit is in megabytes**, internally a 64-bit byte counter.

- `type` ∈ `H` (hourly), `D` (daily), `W` (weekly), `M` (monthly) — the
  reset period, per counter.
- `number` = the record position in the binary counter file. `0` means
  **not persisted** (lost on restart/reload); nonzero must be unique.
  We assign one stable record number per user (the users table's row id
  works; see note in §2.5).

### 2.2 What "in" and "out" count

Verified in `limiter.c`/`auth.c`: `countin` accumulates `statssrv64` =
**bytes received from the target server (user downloads)**; `countout`
accumulates `statscli64` = **bytes sent to the target (user uploads)**.
This matches user intuition (in = download). `countall` covers both.

### 2.3 Enforcement is immediate and server-side

Two enforcement points (this is the strong result):

1. **New connections**: at auth time (`auth.c` `doauth`), if
   `tc->traflim64 <= tc->traf64`, auth returns error 10 ("Traffic limit
   exceeded") → connection refused. Otherwise the connection gets
   `maxtrafin64 = traflim64 - traf64` (remaining allowance).
2. **Established connections**: the data pump (`sockmap.c`) terminates
   the connection with RETURN(10) the moment its transfer exceeds the
   remaining allowance captured at connect time.

So overshoot is bounded by one connection's in-flight buffers, and the
limit cannot be bypassed by keeping a connection open. No control-plane
involvement whatsoever — quota enforcement is fully in the data plane,
satisfying the plane-separation principle.

### 2.4 Persistence and reset

`dumpcounters()` (called every minute from `cyclestep`, and on every
reload/exit) writes `counter_record {traf64, cleared, updated}` per
numbered counter to the binary `3CF` counter file, then resets any
counter whose `type` period has elapsed (`timechanged(cleared, now,
type)` → `traf64 = 0, cleared = now`). Crash cost: up to one minute of
counter data lost. **Reload is safe** — dump happens before the old
counter list is freed (§1.2).

### 2.5 Reset boundary quirk (design decision)

The reset boundary is "the last dump time crossed a period boundary"
(compares `tm_yday`/`tm_mon`/etc. of `cleared` vs now) — i.e., a DAILY
counter resets at the first dump after local midnight, not exactly at
midnight, and `cleared` timestamps use **local time**. xoxproxy treats
the 3proxy counter as the enforcement mechanism (approximate boundary,
±1 min) while the authoritative usage ledger for the dashboard/billing
is the control plane's own accounting from logs (Phase 7), which uses
exact UTC period boundaries. The two are allowed to differ by the
boundary skew; the quota is the guardrail, the ledger is the record.

The user's record number must be **stable across config regeneration**
or counters reset on every push. The users table already has an integer
row id → use it as the counter record number (never 0).

## 3. Engine credentials — BLAKE2b-crypt (`CR:$3$...`)

The `users` directive accepts cleartext (`CL`), MD5-crypt (`$1$`,
requires OpenSSL build), and BLAKE2b-crypt (`$3$`, **always available**).
xoxproxy uses `$3$` so the engine config never contains a plaintext
(or reversibly-derived) password — per the standing constraint.

Exact algorithm, verified from `src/3proxy_crypt.c` (`mycrypt`, `$3$`
branch) and cross-checked by compiling and running the real utility:

```
digest  = BLAKE2b-128( password_bytes || 0x00 || salt_bytes )
```

(the `strlen(pw)+1` in the C source includes the terminating NUL; the
salt is appended **without** one; 16-byte unkeyed BLAKE2b digest).

The 16 digest bytes are then encoded with the traditional crypt base64
alphabet `./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`
in the MD5-crypt arrangement:

```
groups: [0,6,12] [1,7,13] [2,8,14] [3,9,15] [4,10,5] [11]
each 3-byte group (big-endian, last group 1 byte) → 4 chars (last → 2)
```

Final form: `$3$<salt>$<22 chars>`. In the config the whole entry is
double-quoted (a leading `$` would otherwise be parsed as an include
directive): `users "alice:CR:$3$salt$hash"`.

Verified test vectors generated by the real `3proxy_crypt` binary
(compiled from upstream source):

| salt | password | hash |
|---|---|---|
| `testsalt` | `hunter2-password` | `$3$testsalt$6/A9E8lvI/V3WZcOHwGL71` |
| `s1` | `p` | `$3$s1$r3LV1UwVOESoo9mQu0tUc.` |
| `abcdefghijklmnopqrstuvwxyz0123456789` | `correct-staple-9x` | `$3$abcdefghijklmnopqrstuvwxyz0123456789$oUqnrUyusM6TDUdw7eMtU/` |

## 4. Config injection surface (from the parsers)

- `h_users`: tokens are whitespace-split; first `:` separates username
  from password spec. **Usernames must never contain whitespace, `:`,
  or `"`** — otherwise a hostile username becomes a new config directive
  (config injection = the engine-side equivalent of command injection).
  xoxproxy usernames are machine-generated but validated anyway
  (`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`), because controls must hold for
  crafted input, not just for what our UI produces.
- Log format strings and paths are generated by us from validated
  config, never from user input.
- Counter numbers are integers rendered with `%d`.

## 5. Traffic accounting ingestion

3proxy writes one log record per connection at close (plus mid-stream
records only if `logdump` is configured — we do NOT configure it, so
exactly one record per connection; records are cumulative-per-connection
and would double-count if summed). Long-lived SOCKS connections report
their total at close; live in-flight usage is available from the binary
counter file (format now known: `3CF` header + fixed records — Phase 7
can read it directly for real-time display).

Generated `logformat` (all fields we control or validate; `%T` last):

```
logformat "G%t.%. %N.%p %E %U %C:%c %R:%r %O %I %h %T"
```

- `G` = GMT timestamps; `%t.%.` = unix seconds.milliseconds
- `%U` username (validated charset, no spaces), `%C:%c` client,
  `%R:%r` target, `%O` bytes to target (upload), `%I` bytes from target
  (download), `%E` error code (10 = quota exceeded)
- Rotation: `log <file> D` + `rotate N`; ingestion tails and rotates
  with it (Phase 7).

## 6. Actions taken from this spike

1. Deploy/reload uses **SIGUSR1** to the PID from `pidfile` — never
   SIGHUP (release-blocking bug avoided).
2. Config generation includes `pidfile`, `config` (self-reference for
   reload), `counter` file path, and one `countin`/`countout`/
   `countall` per quota, keyed by stable record number.
3. Engine credentials use `CR:$3$` BLAKE2b-crypt, implemented in Go
   with the upstream vectors above as regression tests.
4. Usernames are validated against a strict charset at the engine
   boundary; anything that fails validation is rejected before
   rendering (config-injection defense, server-side).
5. `noforce` is never emitted (force re-auth on reload = immediate
   revocation of live connections).
6. Follow-up (scheduled Phase 11): a CI integration job that builds
   3proxy on Ubuntu and exercises reload + quota end-to-end against a
   real daemon, to guard against upstream behavior changes.
