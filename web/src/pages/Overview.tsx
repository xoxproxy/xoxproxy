import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { LiveSnapshot, ProxyUser, SystemStatus, UsagePeriod } from "../api/client";
import { Badge, PageHeader, StatCard, StatusDot } from "../components/ui";
import { useApi, useInterval, useLiveStream } from "../lib/hooks";
import { formatBytes, formatNumber, formatUptime } from "../lib/format";

interface TrafficResponse {
  days: number;
  history: UsagePeriod[];
  live: LiveSnapshot;
}

// Overview: stat tiles + traffic history + live panel. Live data comes
// from the SSE stream (2s ticks); slower-moving facts (users count,
// system status) refresh on a 30s interval — different frequencies by
// importance, per the real-time rules.
export default function Overview() {
  const traffic = useApi<TrafficResponse>("/api/v1/analytics/traffic?days=30");
  const users = useApi<{ users: ProxyUser[] }>("/api/v1/users");
  const system = useApi<SystemStatus>("/api/v1/system/status");
  const { tick, connected } = useLiveStream();

  useInterval(() => {
    users.reload();
    system.reload();
  }, 30_000);

  const history = traffic.data?.history ?? [];
  const live = tick?.analytics ?? traffic.data?.live ?? null;
  const activeUsers = (users.data?.users ?? []).filter((u) => u.status === "active").length;
  const totalUsers = users.data?.users?.length ?? 0;

  const chart = history.map((p) => ({
    day: new Date(p.period_start).toLocaleDateString(undefined, { month: "short", day: "numeric" }),
    down: p.bytes_in,
    up: p.bytes_out,
  }));

  const monthlyIn = history.reduce((s, p) => s + p.bytes_in, 0);
  const monthlyOut = history.reduce((s, p) => s + p.bytes_out, 0);

  const engineRunning = system.data?.engine_running ?? false;
  const uptime = system.data?.uptime_seconds ?? 0;

  return (
    <>
      <PageHeader
        title="Overview"
        actions={
          connected ? (
            <Badge tone="success"><span className="mr-1 inline-block h-[6px] w-[6px] rounded-[--radius-circle] bg-success" />live</Badge>
          ) : (
            <Badge tone="warning">connecting</Badge>
          )
        }
      />

      {/* Stat tiles */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard
          label="Proxy status"
          value={
            <span className="inline-flex items-center gap-2">
              <StatusDot tone={engineRunning ? "success" : "error"} />
              {engineRunning ? "Running" : "Stopped"}
            </span>
          }
          hint={`uptime ${formatUptime(uptime)}`}
        />
        <StatCard
          label="Active users"
          value={`${activeUsers}`}
          hint={`${totalUsers} total`}
        />
        <StatCard
          label="Today's traffic"
          value={live ? formatBytes(live.bytes_in + live.bytes_out) : "—"}
          hint={live ? `${formatNumber(live.requests)} requests` : undefined}
        />
        <StatCard
          label="30-day traffic"
          value={formatBytes(monthlyIn + monthlyOut)}
          hint={`↓ ${formatBytes(monthlyIn)} · ↑ ${formatBytes(monthlyOut)}`}
        />
      </div>

      {/* Traffic chart + live panel */}
      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <div className="rounded-[--radius-lg] border border-line-2 bg-surface-1 p-4 shadow-card lg:col-span-2">
          <h2 className="text-[length:var(--font-s)] font-semibold text-secondary">
            Traffic — last 30 days
          </h2>
          <div className="mt-3 h-[260px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chart} margin={{ top: 4, right: 4, bottom: 0, left: 0 }}>
                <defs>
                  <linearGradient id="gDown" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--brand-primary)" stopOpacity={0.28} />
                    <stop offset="100%" stopColor="var(--brand-primary)" stopOpacity={0.02} />
                  </linearGradient>
                  <linearGradient id="gUp" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--success-500)" stopOpacity={0.24} />
                    <stop offset="100%" stopColor="var(--success-500)" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="var(--border-1)" vertical={false} />
                <XAxis dataKey="day" tick={{ fontSize: 11, fill: "var(--text-caption)" }}
                  tickLine={false} axisLine={{ stroke: "var(--border-2)" }} interval="preserveStartEnd" />
                <YAxis tick={{ fontSize: 11, fill: "var(--text-caption)" }}
                  tickLine={false} axisLine={false} width={56}
                  tickFormatter={(v: number) => formatBytes(v).replace(" ", "")} />
                <Tooltip
                  formatter={(v: number | string, name: string) => [formatBytes(Number(v)), name === "down" ? "Download" : "Upload"]}
                  labelStyle={{ color: "var(--text-primary)" }}
                  contentStyle={{
                    background: "var(--surface-2)",
                    border: "1px solid var(--border-2)",
                    borderRadius: "var(--radius-sm)",
                    fontSize: "12px",
                    color: "var(--text-primary)",
                  }}
                />
                <Area type="monotone" dataKey="down" stroke="var(--brand-primary)" strokeWidth={1.8} fill="url(#gDown)" />
                <Area type="monotone" dataKey="up" stroke="var(--success-500)" strokeWidth={1.8} fill="url(#gUp)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Live panel */}
        <div className="rounded-[--radius-lg] border border-line-2 bg-surface-1 p-4 shadow-card">
          <h2 className="text-[length:var(--font-s)] font-semibold text-secondary">
            Live — today
          </h2>
          <dl className="mt-3 space-y-4">
            <LiveRow label="Requests" value={live ? formatNumber(live.requests) : "—"} />
            <LiveRow label="Blocked" value={live ? formatNumber(live.blocked) : "—"}
              tone={live && live.blocked > 0 ? "error" : undefined} />
            <LiveRow label="Downloaded" value={live ? formatBytes(live.bytes_in) : "—"} />
            <LiveRow label="Uploaded" value={live ? formatBytes(live.bytes_out) : "—"} />
            <LiveRow label="CPU" value={tick?.cpu_percent !== undefined ? `${tick.cpu_percent.toFixed(0)}%` : "—"} />
            <LiveRow
              label="RAM"
              value={
                tick && tick.ram_used !== undefined && tick.ram_total
                  ? `${Math.round((tick.ram_used / tick.ram_total) * 100)}%`
                  : "—"
              }
            />
          </dl>
          {system.data?.version && (
            <p className="mt-5 border-t border-line-1 pt-3 text-[length:var(--font-xs)] text-caption">
              xoxproxy v{system.data.version}
              {system.data.tls_enabled ? " · TLS" : ""}
            </p>
          )}
        </div>
      </div>
    </>
  );
}

function LiveRow({ label, value, tone }: {
  label: string;
  value: React.ReactNode;
  tone?: "error";
}) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <dt className="text-[length:var(--font-s)] text-secondary">{label}</dt>
      <dd className={["text-[length:var(--font-m)] font-semibold tabular-nums",
        tone === "error" ? "text-error" : "text-primary"].join(" ")}>
        {value}
      </dd>
    </div>
  );
}
