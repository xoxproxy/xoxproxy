// API client. Mirrors the Go control plane's conventions:
//   - session cookie is HttpOnly (credentials: same-origin)
//   - every non-GET/HEAD request carries the X-CSRF-Token header
//   - errors use the {error:{code,message,request_id}} envelope
//   - 401 means the session is gone → redirect to login

export class ApiError extends Error {
  code: string;
  requestId: string;
  status: number;

  constructor(status: number, code: string, message: string, requestId: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

// CSRF token: captured from login/session responses, held in memory only.
let csrfToken: string | null = null;

export function setCsrfToken(token: string) {
  csrfToken = token;
}

export function clearCsrfToken() {
  csrfToken = null;
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (method !== "GET" && method !== "HEAD" && csrfToken) {
    headers["X-CSRF-Token"] = csrfToken;
  }

  let resp: Response;
  try {
    resp = await fetch(path, {
      method,
      headers,
      credentials: "same-origin",
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (err) {
    throw new ApiError(0, "NETWORK", "network error", "");
  }

  if (resp.status === 401) {
    // Session gone (expired, revoked, or never existed). Send the user to
    // the login page, preserving the attempted location.
    csrfToken = null;
    if (!location.pathname.startsWith("/login")) {
      const next = encodeURIComponent(location.pathname + location.search);
      location.assign(`/login?next=${next}`);
    }
    throw new ApiError(401, "UNAUTHORIZED", "session expired", "");
  }

  if (resp.status === 204) {
    return undefined as T;
  }

  let payload: unknown;
  const text = await resp.text();
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = null;
    }
  }

  if (!resp.ok) {
    const env = payload as { error?: { code?: string; message?: string; request_id?: string } } | null;
    throw new ApiError(
      resp.status,
      env?.error?.code ?? "UNKNOWN",
      env?.error?.message ?? `request failed (${resp.status})`,
      env?.error?.request_id ?? resp.headers.get("X-Request-ID") ?? "",
    );
  }

  return payload as T;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body ?? {}),
  patch: <T>(path: string, body: unknown) => request<T>("PATCH", path, body),
  del: <T>(path: string, body?: unknown) => request<T>("DELETE", path, body),
};

// --- SSE subscription ------------------------------------------------
// The live stream sends one "tick" event every 2 seconds. Reconnect with
// backoff so a server restart doesn't kill the dashboard permanently.

export function subscribeStream(
  onTick: (data: StreamTick) => void,
): () => void {
  const es = new EventSource("/api/v1/analytics/stream");
  es.addEventListener("tick", (ev) => {
    try {
      onTick(JSON.parse((ev as MessageEvent).data));
    } catch {
      // Malformed tick: skip, the next one is 2s away.
    }
  });
  return () => es.close();
}

export interface StreamTick {
  analytics: LiveSnapshot;
  cpu_percent?: number;
  ram_used?: number;
  ram_total?: number;
}

// --- shared types (mirror the Go response shapes) ---------------------

export interface LiveSnapshot {
  day: string;
  bytes_in: number;
  bytes_out: number;
  requests: number;
  blocked: number;
  ingested: number;
  overflowed: number;
  dropped: number;
  log_offset: number;
  malformed_lines: number;
  ring_enabled: boolean;
}

export interface ProxyUser {
  id: number;
  username: string;
  status: "active" | "disabled" | "expired";
  allowed_protocols: string[];
  download_limit_bps: number;
  upload_limit_bps: number;
  max_connections: number;
  quota_bytes_daily: number;
  quota_bytes_monthly: number;
  expires_at: string | null;
  version: number;
  created_at: string;
  updated_at: string;
  last_seen_at: string | null;
}

export interface NewCredential extends ProxyUser {
  password: string;
}

export interface UsagePeriod {
  period_start: string;
  granularity: string;
  bytes_in: number;
  bytes_out: number;
  connections: number;
}

export interface DestinationStat {
  username: string;
  host: string;
  port: number;
  protocol: string;
  requests: number;
  blocked: number;
  bytes_in: number;
  bytes_out: number;
  last_seen: string;
}

export interface LiveConnection {
  time: string;
  username: string;
  protocol: string;
  host: string;
  port: number;
  client_ip: string;
  blocked: boolean;
  bytes_in: number;
  bytes_out: number;
}

export interface AuditEntry {
  id: number;
  timestamp: string;
  actor: string;
  action: string;
  target: string;
  request_id: string;
  source_ip: string;
  result: string;
  detail: string;
}

export interface ConfigVersion {
  revision: number;
  generated_at: string;
  generated_by: string;
  reason: string;
  validation_status: string;
  deployment_status: string;
  checksum: string;
}

export interface SystemStatus {
  hostname: string;
  os: string;
  platform: string;
  kernel: string;
  arch: string;
  uptime_seconds: number;
  public_ip: string;
  engine_running: boolean;
  last_deploy: ConfigVersion | null;
  proxy_ports: { http: number; socks5: number };
  tls_enabled: boolean;
  version: string;
}

export interface SystemResources {
  cpu_percent: number;
  cores: number;
  load1: number;
  load5: number;
  load15: number;
  mem_total: number;
  mem_used: number;
  swap_total: number;
  swap_used: number;
  disk_total: number;
  disk_used: number;
  net_rx_bytes: number;
  net_tx_bytes: number;
}
