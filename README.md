# xoxproxy

Self-hosted proxy management appliance: turn a Linux VPS into a managed,
authenticated HTTP/HTTPS/SOCKS5 proxy server with users, bandwidth limits,
quotas, expiration, analytics, and a real-time dashboard — without ever
risking an accidental open proxy.

## Install

One command, on a fresh Linux VPS:

```sh
curl -fsSL https://raw.githubusercontent.com/xoxproxy/xoxproxy/main/install.sh | sh
```

The script downloads the latest release binary for your platform, installs
it to `/usr/local/bin/xoxproxy`, and creates `/etc/xoxproxy`. Then:

```sh
sudo xoxproxy admin create -username admin -generate   # one-time setup
sudo systemctl enable --now xoxproxy                    # systemd unit installed by the script
```

The dashboard listens on `http://127.0.0.1:8080` by default — put Caddy or
another TLS proxy in front of it for remote access.

## Features

- **Authenticated proxying** — HTTP, HTTPS CONNECT, and SOCKS5 with
  per-user credentials; nothing is proxied without an account
- **User lifecycle** — create, edit, disable, expire; per-user bandwidth
  limits, daily/monthly quotas, max connections, expiry dates
- **One-time credentials** — passwords are shown exactly once at create or
  rotate; copy-ready proxy URLs included
- **Real-time dashboard** — live connections, bandwidth, and traffic over
  SSE; light/dark themes; fully responsive
- **Analytics** — traffic history, per-user reports, top and blocked
  destinations; aggregated views, never raw event dumps
- **Server monitoring** — CPU, RAM, disk, network, uptime, public IP
- **Audit trail** — append-only log of every privileged action
- **Atomic config deploys** — every change renders, validates, and
  installs a new engine config; failed deploys roll back automatically
- **Single static binary** — SQLite embedded, no runtime dependencies

## How it works

The proxy **data plane** ([3proxy](https://github.com/3proxy/3proxy))
serves traffic from two files on disk and never depends on the **control
plane** (the xoxproxy binary + dashboard). If the dashboard, API, or
database fails, established proxy traffic continues uninterrupted.

xoxproxy manages everything else: users, credential hashing, config
generation, safe reloads, traffic accounting, and monitoring.

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, data flows, trust/failure boundaries, deployment model |
| [docs/DESIGN-REVIEW.md](docs/DESIGN-REVIEW.md) | Architectural and security risk register, tradeoffs |
| [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) | Assets, adversaries, STRIDE analysis |
| [docs/SECURITY-TESTING.md](docs/SECURITY-TESTING.md) | Security acceptance criteria, attack-case matrix |
| [examples/](examples/) | Example configuration |

## Quick start (from source)

```sh
git clone https://github.com/xoxproxy/xoxproxy
cd xoxproxy
make build    # ./bin/xoxproxy
```

Requires Go 1.25+. See `xoxproxy help` for all commands (server, admin,
users, deploy, config validate, version).

### Dashboard development

The dashboard is a React + TypeScript SPA embedded in the binary. Its
build output is committed, so building xoxproxy never requires Node.
To hack on the frontend, edit `web/` and run `pnpm dev` (proxies `/api`
to a local server), then commit a fresh build with `make web`.

## Security notes

- The dashboard binds to loopback by default; a fresh install is never
  accidentally internet-exposed
- Admin sessions use server-side cookies with CSRF protection and
  login throttling
- Proxy credentials use salted, memory-hard hashing in the engine and a
  separate verifier for the control plane
- The rendered engine config contains credential verifiers and never
  enters the database or any API response

Report vulnerabilities by opening a security advisory on this repository.

## License

[MIT](LICENSE)
