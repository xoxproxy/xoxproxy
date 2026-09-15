import { SystemResources, SystemStatus } from "../api/client";
import { Badge, PageHeader, StatCard, StatusDot } from "../components/ui";
import { useApi, useLiveStream } from "../lib/hooks";
import { formatBytes, formatDateTime, formatUptime } from "../lib/format";

// Server: host identity + resource meters. CPU/RAM also arrive over the
// SSE stream; the 5s REST refresh is the fallback when it's disconnected.
export default function Server() {
  const status = useApi<SystemStatus>("/api/v1/system/status");
  const resources = useApi<SystemResources>("/api/v1/system/resources");
  const { tick } = useLiveStream();

  if (status.error) {
    return (
      <>
        <PageHeader title="Server" />
        <p className="text-[length:var(--font-s)] text-error">{status.error}</p>
      </>
    );
  }

  const s = status.data;
  const r = resources.data;
  const cpu = tick?.cpu_percent ?? r?.cpu_percent ?? null;
  const ramUsed = tick?.ram_used ?? r?.mem_used ?? null;
  const ramTotal = tick?.ram_total ?? r?.mem_total ?? null;

  return (
    <>
      <PageHeader
        title="Server"
        actions={
          s ? (
            <Badge tone={s.engine_running ? "success" : "error"}>
              {s.engine_running ? "engine running" : "engine stopped"}
            </Badge>
          ) : undefined
        }
      />

      {/* Identity */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard
          label="Host"
          value={s?.hostname ?? "—"}
          hint={s ? `${s.os} · ${s.arch}` : undefined}
        />
        <StatCard
          label="Uptime"
          value={s ? formatUptime(s.uptime_seconds) : "—"}
          hint={s ? `kernel ${s.kernel}` : undefined}
        />
        <StatCard
          label="Public IP"
          value={s?.public_ip || "unknown"}
          hint={s?.tls_enabled ? "TLS enabled" : "plain HTTP"}
        />
        <StatCard
          label="Proxy ports"
          value={s ? `${s.proxy_ports.http} / ${s.proxy_ports.socks5}` : "—"}
          hint="HTTP / SOCKS5"
        />
      </div>

      {/* Resource meters */}
      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <MeterCard
          title="CPU"
          value={cpu !== null ? `${cpu.toFixed(0)}%` : "—"}
          pct={cpu ?? 0}
          sub={r ? `${r.cores} cores · load ${r.load1.toFixed(2)} ${r.load5.toFixed(2)} ${r.load15.toFixed(2)}` : undefined}
        />
        <MeterCard
          title="RAM"
          value={
            ramUsed !== null && ramTotal
              ? `${Math.round((ramUsed / ramTotal) * 100)}%`
              : "—"
          }
          pct={ramUsed !== null && ramTotal ? (ramUsed / ramTotal) * 100 : 0}
          sub={
            ramUsed !== null && ramTotal
              ? `${formatBytes(ramUsed)} of ${formatBytes(ramTotal)}`
              : undefined
          }
        />
        <MeterCard
          title="Disk"
          value={
            r && r.disk_total ? `${Math.round((r.disk_used / r.disk_total) * 100)}%` : "—"
          }
          pct={r && r.disk_total ? (r.disk_used / r.disk_total) * 100 : 0}
          sub={r && r.disk_total ? `${formatBytes(r.disk_used)} of ${formatBytes(r.disk_total)}` : undefined}
        />
      </div>

      {/* Network + deploy */}
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div className="rounded-[--radius-lg] border border-line-2 bg-surface-1 p-4 shadow-card">
          <h2 className="text-[length:var(--font-s)] font-semibold text-secondary">Network</h2>
          <dl className="mt-3 space-y-[10px] text-[length:var(--font-s)]">
            <div className="flex justify-between">
              <dt className="text-secondary">Received</dt>
              <dd className="tabular-nums font-medium">{r ? formatBytes(r.net_rx_bytes) : "—"}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-secondary">Sent</dt>
              <dd className="tabular-nums font-medium">{r ? formatBytes(r.net_tx_bytes) : "—"}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-secondary">Platform</dt>
              <dd className="font-medium">{s?.platform ?? "—"}</dd>
            </div>
          </dl>
        </div>

        <div className="rounded-[--radius-lg] border border-line-2 bg-surface-1 p-4 shadow-card">
          <h2 className="text-[length:var(--font-s)] font-semibold text-secondary">
            Last deployment
          </h2>
          {s?.last_deploy ? (
            <dl className="mt-3 space-y-[10px] text-[length:var(--font-s)]">
              <div className="flex justify-between">
                <dt className="text-secondary">Revision</dt>
                <dd className="font-medium tabular-nums">#{s.last_deploy.revision}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-secondary">When</dt>
                <dd className="font-medium">{formatDateTime(s.last_deploy.generated_at)}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-secondary">Trigger</dt>
                <dd className="font-medium">{s.last_deploy.reason}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-secondary">Status</dt>
                <dd>
                  <span className="inline-flex items-center gap-2 font-medium">
                    <StatusDot
                      tone={
                        s.last_deploy.deployment_status === "deployed" || s.last_deploy.deployment_status === "unchanged"
                          ? "success"
                          : s.last_deploy.deployment_status === "failed"
                            ? "error"
                            : "warning"
                      }
                    />
                    {s.last_deploy.deployment_status}
                  </span>
                </dd>
              </div>
            </dl>
          ) : (
            <p className="mt-6 text-[length:var(--font-s)] text-caption">
              No deployments recorded yet.
            </p>
          )}
          {s && (
            <p className="mt-5 border-t border-line-1 pt-3 text-[length:var(--font-xs)] text-caption">
              xoxproxy v{s.version}
            </p>
          )}
        </div>
      </div>
    </>
  );
}

function MeterCard({ title, value, pct, sub }: {
  title: string;
  value: string;
  pct: number;
  sub?: string;
}) {
  const clamped = Math.max(0, Math.min(100, pct));
  const danger = clamped >= 90, warn = clamped >= 70;
  return (
    <div className="rounded-[--radius-lg] border border-line-2 bg-surface-1 p-4 shadow-card">
      <div className="flex items-baseline justify-between">
        <h2 className="text-[length:var(--font-s)] font-semibold text-secondary">{title}</h2>
        <span className="text-[22px] font-semibold leading-8 tracking-tight tabular-nums">
          {value}
        </span>
      </div>
      <div className="mt-3 h-[6px] overflow-hidden rounded-[--radius-pill] bg-[var(--interactive-hover)]">
        <div
          className={["h-full rounded-[--radius-pill] transition-[width] duration-[var(--duration-slow)]",
            danger ? "bg-error" : warn ? "bg-warning" : "bg-brand"].join(" ")}
          style={{ width: `${clamped}%` }}
        />
      </div>
      {sub && <p className="mt-2 text-[length:var(--font-xs)] text-caption">{sub}</p>}
    </div>
  );
}
