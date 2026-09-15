import { useState } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { DestinationStat, UsagePeriod } from "../api/client";
import DataTable, { Column } from "../components/DataTable";
import { PageHeader } from "../components/ui";
import { useApi } from "../lib/hooks";
import { formatBytes, formatNumber } from "../lib/format";

interface TrafficResponse {
  days: number;
  history: UsagePeriod[];
}

const RANGES = [7, 30, 90] as const;

// Analytics: aggregated views only (day-granularity history, top-N
// destinations) — never raw events, per the GUIDE rule.
export default function Analytics() {
  const [days, setDays] = useState<(typeof RANGES)[number]>(30);

  const traffic = useApi<TrafficResponse>(`/api/v1/analytics/traffic?days=${days}`);
  const dests = useApi<{ destinations: DestinationStat[] }>(
    `/api/v1/analytics/destinations?days=${days}&limit=10`,
  );
  const blocked = useApi<{ blocked: DestinationStat[] }>(
    `/api/v1/analytics/blocked?days=${days}&limit=10`,
  );

  const history = traffic.data?.history ?? [];
  const totalIn = history.reduce((s, p) => s + p.bytes_in, 0);
  const totalOut = history.reduce((s, p) => s + p.bytes_out, 0);
  const totalConn = history.reduce((s, p) => s + p.connections, 0);

  const chart = history.map((p) => ({
    day: new Date(p.period_start).toLocaleDateString(undefined, { month: "short", day: "numeric" }),
    down: p.bytes_in,
    up: p.bytes_out,
    conn: p.connections,
  }));

  // Per-user traffic over the window: sum of history isn't per-user from
  // the global endpoint, so we render request counts by destination
  // leaders instead — the per-user table uses the users list + analytics
  // endpoints on the detail page. Here: top destinations carry the load.
  const byUser = new Map<string, number>();
  for (const d of dests.data?.destinations ?? []) {
    byUser.set(d.username, (byUser.get(d.username) ?? 0) + d.bytes_in + d.bytes_out);
  }
  const userBars = [...byUser.entries()]
    .map(([username, bytes]) => ({ username, bytes }))
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 8);

  const destColumns: Column<DestinationStat>[] = [
    { key: "host", header: "Destination", render: (d) => `${d.host}:${d.port}`, sortValue: (d) => d.host },
    { key: "user", header: "User", render: (d) => <span className="text-secondary">{d.username}</span> },
    { key: "protocol", header: "Protocol", render: (d) => <span className="text-secondary">{d.protocol}</span> },
    { key: "requests", header: "Requests", render: (d) => <span className="tabular-nums">{formatNumber(d.requests)}</span>, align: "right", sortValue: (d) => d.requests },
    { key: "bytes", header: "Traffic", render: (d) => <span className="tabular-nums text-secondary">{formatBytes(d.bytes_in + d.bytes_out)}</span>, align: "right", sortValue: (d) => d.bytes_in + d.bytes_out },
    { key: "last", header: "Last seen", render: (d) => <span className="text-caption">{new Date(d.last_seen).toLocaleDateString()}</span> },
  ];

  const blockedColumns: Column<DestinationStat>[] = [
    { key: "host", header: "Destination", render: (d) => `${d.host}:${d.port}` },
    { key: "user", header: "User", render: (d) => <span className="text-secondary">{d.username}</span> },
    { key: "blocked", header: "Blocked", render: (d) => <span className="tabular-nums text-error">{formatNumber(d.blocked)}</span>, align: "right", sortValue: (d) => d.blocked },
    { key: "requests", header: "Total requests", render: (d) => <span className="tabular-nums text-secondary">{formatNumber(d.requests)}</span>, align: "right", sortValue: (d) => d.requests },
  ];

  return (
    <>
      <PageHeader
        title="Analytics"
        actions={
          <div className="inline-flex gap-1 rounded-[--radius-control] bg-[var(--interactive-hover)] p-1">
            {RANGES.map((r) => (
              <button
                key={r}
                onClick={() => setDays(r)}
                className={[
                  "h-[var(--control-s)] rounded-[--radius-xs] px-3 text-[length:var(--font-s)] font-medium",
                  "transition-colors duration-[var(--duration)]",
                  days === r ? "bg-surface-1 text-primary shadow-card" : "text-secondary hover:text-primary",
                ].join(" ")}
              >
                {r}d
              </button>
            ))}
          </div>
        }
      />

      {/* Summary strip */}
      <div className="grid grid-cols-3 gap-4">
        <SummaryTile label="Downloads" value={formatBytes(totalIn)} />
        <SummaryTile label="Uploads" value={formatBytes(totalOut)} />
        <SummaryTile label="Connections" value={formatNumber(totalConn)} />
      </div>

      {/* Traffic over time */}
      <div className="mt-4 rounded-[--radius-lg] border border-line-2 bg-surface-1 p-4 shadow-card">
        <h2 className="text-[length:var(--font-s)] font-semibold text-secondary">
          Traffic over time
        </h2>
        <div className="mt-3 h-[240px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chart} margin={{ top: 4, right: 4, bottom: 0, left: 0 }}>
              <defs>
                <linearGradient id="aDown" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--brand-primary)" stopOpacity={0.28} />
                  <stop offset="100%" stopColor="var(--brand-primary)" stopOpacity={0.02} />
                </linearGradient>
                <linearGradient id="aUp" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--success-500)" stopOpacity={0.24} />
                  <stop offset="100%" stopColor="var(--success-500)" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="var(--border-1)" vertical={false} />
              <XAxis dataKey="day" tick={{ fontSize: 11, fill: "var(--text-caption)" }} tickLine={false} axisLine={{ stroke: "var(--border-2)" }} interval="preserveStartEnd" />
              <YAxis tick={{ fontSize: 11, fill: "var(--text-caption)" }} tickLine={false} axisLine={false} width={56} tickFormatter={(v: number) => formatBytes(v).replace(" ", "")} />
              <Tooltip
                formatter={(v: number | string, name: string) => [formatBytes(Number(v)), name === "down" ? "Download" : "Upload"]}
                labelStyle={{ color: "var(--text-primary)" }}
                contentStyle={{ background: "var(--surface-2)", border: "1px solid var(--border-2)", borderRadius: "var(--radius-sm)", fontSize: "12px", color: "var(--text-primary)" }}
              />
              <Area type="monotone" dataKey="down" stackId="t" stroke="var(--brand-primary)" strokeWidth={1.8} fill="url(#aDown)" />
              <Area type="monotone" dataKey="up" stackId="t" stroke="var(--success-500)" strokeWidth={1.8} fill="url(#aUp)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Connections + per-user traffic */}
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div className="rounded-[--radius-lg] border border-line-2 bg-surface-1 p-4 shadow-card">
          <h2 className="text-[length:var(--font-s)] font-semibold text-secondary">
            Connections per day
          </h2>
          <div className="mt-3 h-[180px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chart} margin={{ top: 4, right: 4, bottom: 0, left: 0 }}>
                <CartesianGrid stroke="var(--border-1)" vertical={false} />
                <XAxis dataKey="day" tick={{ fontSize: 11, fill: "var(--text-caption)" }} tickLine={false} axisLine={{ stroke: "var(--border-2)" }} interval="preserveStartEnd" />
                <YAxis tick={{ fontSize: 11, fill: "var(--text-caption)" }} tickLine={false} axisLine={false} width={40} />
                <Tooltip
                  formatter={(v: number | string) => [formatNumber(Number(v)), "Connections"]}
                  labelStyle={{ color: "var(--text-primary)" }}
                  contentStyle={{ background: "var(--surface-2)", border: "1px solid var(--border-2)", borderRadius: "var(--radius-sm)", fontSize: "12px", color: "var(--text-primary)" }}
                />
                <Bar dataKey="conn" fill="var(--brand-primary)" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="rounded-[--radius-lg] border border-line-2 bg-surface-1 p-4 shadow-card">
          <h2 className="text-[length:var(--font-s)] font-semibold text-secondary">
            Traffic by user
          </h2>
          {userBars.length === 0 ? (
            <p className="mt-6 text-[length:var(--font-s)] text-caption">
              No traffic recorded in this window.
            </p>
          ) : (
            <div className="mt-3 h-[180px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={userBars} layout="vertical" margin={{ top: 4, right: 12, bottom: 0, left: 8 }}>
                  <CartesianGrid stroke="var(--border-1)" horizontal={false} />
                  <XAxis type="number" tick={{ fontSize: 11, fill: "var(--text-caption)" }} tickLine={false} axisLine={false} tickFormatter={(v: number) => formatBytes(v).replace(" ", "")} />
                  <YAxis type="category" dataKey="username" tick={{ fontSize: 11, fill: "var(--text-caption)" }} tickLine={false} axisLine={false} width={72} />
                  <Tooltip
                    formatter={(v: number | string) => [formatBytes(Number(v)), "Traffic"]}
                    labelStyle={{ color: "var(--text-primary)" }}
                    contentStyle={{ background: "var(--surface-2)", border: "1px solid var(--border-2)", borderRadius: "var(--radius-sm)", fontSize: "12px", color: "var(--text-primary)" }}
                  />
                  <Bar dataKey="bytes" fill="var(--brand-primary)" radius={[0, 3, 3, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>

      {/* Destinations */}
      <div className="mt-6">
        <h2 className="mb-3 text-[length:var(--font-s)] font-semibold text-secondary">
          Top destinations
        </h2>
        <DataTable
          columns={destColumns}
          rows={dests.data?.destinations ?? []}
          loading={dests.loading}
          emptyLabel="No destination stats in this window"
          rowKey={(d) => `${d.username}:${d.host}:${d.port}`}
        />
      </div>

      {/* Blocked */}
      <div className="mt-6">
        <h2 className="mb-3 text-[length:var(--font-s)] font-semibold text-secondary">
          Blocked destinations
        </h2>
        <DataTable
          columns={blockedColumns}
          rows={blocked.data?.blocked ?? []}
          loading={blocked.loading}
          emptyLabel="Nothing blocked in this window"
          rowKey={(d) => `${d.username}:${d.host}:${d.port}`}
        />
      </div>
    </>
  );
}

function SummaryTile({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-[--radius-lg] border border-line-2 bg-surface-1 p-4 shadow-card">
      <div className="text-[length:var(--font-s)] text-secondary">{label}</div>
      <div className="mt-2 text-[22px] font-semibold leading-8 tracking-tight tabular-nums">
        {value}
      </div>
    </div>
  );
}
