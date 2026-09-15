#!/bin/sh
# xoxproxy one-command installer.
#
#   curl -fsSL https://raw.githubusercontent.com/xoxproxy/xoxproxy/main/install.sh | sh
#
# Installs the latest release binary for the detected platform, creates the
# config/data directories, and installs (but does not start) a systemd unit.
# Safe to re-run: every step is idempotent.
set -eu

REPO="xoxproxy/xoxproxy"
PREFIX="${PREFIX:-/usr/local}"
ETC_DIR="${ETC_DIR:-/etc/xoxproxy}"
DATA_DIR="${DATA_DIR:-/var/lib/xoxproxy}"

log()  { printf '==> %s\n' "$*"; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

# --- platform detection ---------------------------------------------------

OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS" in
  Linux) os="linux" ;;
  *) die "unsupported OS '$OS' — this installer covers Linux; build from source for other platforms" ;;
esac
case "$ARCH" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
  *) die "unsupported architecture '$ARCH'" ;;
esac

# --- prerequisites --------------------------------------------------------

for cmd in curl tar; do
  command -v "$cmd" >/dev/null 2>&1 || die "'$cmd' is required"
done

[ "$(id -u)" -eq 0 ] || die "run as root (e.g. curl … | sudo sh)"

# --- locate the latest release -------------------------------------------

log "finding the latest release"
URL="https://github.com/${REPO}/releases/latest/download/xoxproxy-${os}-${arch}.tar.gz"
ASSET="xoxproxy-${os}-${arch}.tar.gz"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

log "downloading ${ASSET}"
curl -fsSL -o "$TMP/$ASSET" "$URL" \
  || die "download failed — is there a release for ${os}/${arch}? see https://github.com/${REPO}/releases"

log "verifying and unpacking"
tar -xzf "$TMP/$ASSET" -C "$TMP"
[ -f "$TMP/xoxproxy" ] || die "archive did not contain the xoxproxy binary"

# --- install the binary ---------------------------------------------------

log "installing ${PREFIX}/bin/xoxproxy"
install -m 0755 "$TMP/xoxproxy" "${PREFIX}/bin/xoxproxy"
"${PREFIX}/bin/xoxproxy" version || true

# --- directories and config ----------------------------------------------

log "creating ${ETC_DIR} and ${DATA_DIR}"
install -d -m 0750 "$ETC_DIR" "$ETC_DIR/engine" "$DATA_DIR"

if [ ! -f "${ETC_DIR}/config.toml" ]; then
  log "writing default config to ${ETC_DIR}/config.toml"
  cat > "${ETC_DIR}/config.toml" <<'EOF'
# xoxproxy configuration. See https://github.com/xoxproxy/xoxproxy for all options.

[server]
# Loopback by default: the dashboard is reached over an SSH tunnel, or put
# Caddy/nginx (TLS) in front of it for remote access.
listen = "127.0.0.1:8080"
# public_base_url = "https://proxy.example.com"

[database]
path = "/var/lib/xoxproxy/xoxproxy.db"

[engine]
provider = "threeproxy"
binary_path = "/usr/bin/3proxy"
config_dir = "/etc/xoxproxy/engine"

[proxy]
http_port = 3128
socks5_port = 1080

[analytics]
flush_interval = "30s"
queue_size = 4096
verbosity = "detailed"
retention_days = 90
max_destinations_per_user = 256
recent_connections = 200

[log]
level = "info"
EOF
  chmod 0640 "${ETC_DIR}/config.toml"
else
  log "config already exists — leaving it untouched"
fi

# --- data plane -----------------------------------------------------------

# The engine (3proxy) serves traffic; without it the control plane starts
# fine but nothing is proxied. Install it if a package is available.
if ! command -v 3proxy >/dev/null 2>&1; then
  log "note: 3proxy (data plane) is not installed"
  log "install it (e.g. build from https://github.com/3proxy/3proxy) to /usr/bin/3proxy"
  log "the control plane starts regardless and applies config when it appears"
fi

# --- systemd --------------------------------------------------------------

if command -v systemctl >/dev/null 2>&1; then
  log "installing systemd unit"
  cat > /etc/systemd/system/xoxproxy.service <<EOF
[Unit]
Description=xoxproxy control plane
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${PREFIX}/bin/xoxproxy server -config ${ETC_DIR}/config.toml
Restart=on-failure
RestartSec=5

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR} ${ETC_DIR}
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  log "systemd unit installed (not started)"
else
  log "systemd not found — start manually: ${PREFIX}/bin/xoxproxy server -config ${ETC_DIR}/config.toml"
fi

# --- next steps -----------------------------------------------------------

cat <<EOF

xoxproxy installed.

Next:
  1. Create the administrator account:
       sudo ${PREFIX}/bin/xoxproxy admin create -config ${ETC_DIR}/config.toml -username admin -generate
  2. Start the service:
       sudo systemctl enable --now xoxproxy
  3. Open the dashboard at http://127.0.0.1:8080 (use an SSH tunnel for
     remote access, or put Caddy/nginx with TLS in front of it).

EOF
