import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  api,
  AuditEntry,
  DestinationStat,
  LiveConnection,
  ProxyUser,
  UsagePeriod,
} from "../api/client";
import DataTable, { Column } from "../components/DataTable";
import { Badge, Button, Modal, PageHeader } from "../components/ui";
import UserForm, { UserFormValues } from "../components/UserForm";
import { useApi, useInterval } from "../lib/hooks";
import { formatBytes, formatDateTime, formatRelative } from "../lib/format";

interface UserAnalytics {
  user_id: number;
  history: UsagePeriod[];
  destinations: DestinationStat[];
}

export default function UserDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const user = useApi<ProxyUser>(`/api/v1/users/${id}`);
  const analytics = useApi<UserAnalytics>(`/api/v1/analytics/users/${id}?days=30&limit=10`);
  const live = useApi<{ connections: LiveConnection[] }>(`/api/v1/analytics/live`);
  const audit = useApi<{ entries: AuditEntry[] }>(`/api/v1/audit-logs?limit=50`);
  const [editing, setEditing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Live connections and recent activity move; refresh on a slower
  // cadence than the SSE stream since this view is per-user detail.
  useInterval(() => {
    live.reload();
    audit.reload();
  }, 15_000);

  if (user.error) {
    return (
      <>
        <PageHeader title="User" />
        <p className="text-[length:var(--font-s)] text-error">{user.error}</p>
      </>
    );
  }

  const u = user.data;
  if (!u) {
    return (
      <>
        <PageHeader title="User" />
        <p className="text-[length:var(--font-s)] text-caption">Loading…</p>
      </>
    );
  }

  const connections = (live.data?.connections ?? []).filter(
    (c) => c.username === u.username,
  );

  const auditRows = (audit.data?.entries ?? []).filter(
    (e) => e.target === u.username || e.actor === `user:${u.username}`,
  );

  const totalIn = (analytics.data?.history ?? []).reduce((s, p) => s + p.bytes_in, 0);
  const totalOut = (analytics.data?.history ?? []).reduce((s, p) => s + p.bytes_out, 0);

  const chart = (analytics.data?.history ?? []).map((p) => ({
    day: new Date(p.period_start).toLocaleDateString(undefined, { month: "short", day: "numeric" }),
    down: p.bytes_in,
    up: p.bytes_out,
  }));

  const quotaRows = [
    { label: "Daily quota", used: totalIn + totalOut, cap: u.quota_bytes_daily },
    { label: "Monthly quota", used: totalIn + totalOut, cap: u.quota_bytes_monthly },
  ].filter((r) => r.cap > 0);

  const onEdit = async (values: UserFormValues) => {
    try {
      await api.patch<ProxyUser>(`/api/v1/users/${u.id}`, { ...values, version: u.version });
      setEditing(false);
      user.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "update failed");
    }
  };

  const destColumns: Column<DestinationStat>[] = [
    { key: "host", header: "Destination", render: (d) => `${d.host}:${d.port}` },
    { key: "protocol", header: "Protocol", render: (d) => <span className="text-secondary">{d.protocol}</span> },
    { key: "requests", header: "Requests", render: (d) => <span className="tabular-nums">{d.requests}</span>, align: "right", sortValue: (d) => d.requests },
    { key: "blocked", header: "Blocked", render: (d) => <span className={["tabular-nums", d.blocked > 0 ? "text-error" : "text-caption"].join(" ")}>{d.blocked}</span>, align: "right", sortValue: (d) => d.blocked },
    { key: "bytes", header: "Traffic", render: (d) => <span className="tabular-nums text-secondary">{formatBytes(d.bytes_in + d.bytes_out)}</span>, align: "right", sortValue: (d) => d.bytes_in + d.bytes_out },
    { key: "last", header: "Last seen", render: (d) => <span className="text-secondary">{formatRelative(d.last_seen)}</span> },
  ];

  return (
    <>
      <PageHeader
        title={u.username}
        actions={
          <>
            <Button variant="elevated" onClick={() => navigate("/users")}>← Users</Button>
            <Button onClick={() => setEditing(true)}>Edit</Button>
          </>
        }
      />

      {error && <p role="alert" className="mb-4 text-[length:var(--font-s)] text-error">{error}</p>}

      {/* Profile + quota */}
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="rounded-[--radius-lg] border border-line-2 bg-surface-1 p-4 shadow-card">
          <div className="flex items-center gap-3">
            <StatusBadge status={u.status} />
            <span className="text-[length:var(--font-xs)] text-caption">
              created {formatDateTime(u.created_at)}
            </span>
          </div>
          <dl className="mt-4 space-y-[10px] text-[length:var(--font-s)]">
            <Row label="Protocols" value={u.allowed_protocols.map((p) => p.toUpperCase()).join(" · ")} />
            <Row label="Bandwidth" value={u.download_limit_bps ? `${u.download_limit_bps / 1e6} Mbps ↓` : "∞ ↓"} />
            <Row label="Max connections" value={u.max_connections ? String(u.max_connections) : "∞"} />
            <Row label="Expires" value={u.expires_at ? formatDateTime(u.expires_at) : "never"} />
            <Row label="Last seen" value={formatRelative(u.last_seen_at)} />
          </dl>
        </div>

        {/* Quota usage */}
        <div className="rounded-[--radius-lg] border border-line-2 bg-surface-1 p-4 shadow-card lg:col-span-2">
          <h2 className="text-[length:var(--font-s)] font-semibold text-secondary">Quota usage</h2>
          {quotaRows.length === 0 ? (
            <p className="mt-6 text-[length:var(--font-s)] text-caption">
              No quotas set for this user.
            </p>
          ) : (
            <div className="mt-4 space-y-5">
              {quotaRows.map((r) => {
                const pct = Math.min(100, (r.used / r.cap) * 100);
                const danger = pct >= 90, warn = pct >= 70;
                return (
                  <div key={r.label}>
                    <div className="mb-[6px] flex justify-between text-[length:var(--font-s)]">
                      <span className="text-secondary">{r.label}</span>
                      <span className="tabular-nums">
                        {formatBytes(r.used)} / {formatBytes(r.cap)}
                      </span>
                    </div>
                    <div className="h-[6px] overflow-hidden rounded-[--radius-pill] bg-[var(--interactive-hover)]">
                      <div
                        className={["h-full rounded-[--radius-pill] transition-[width] duration-[var(--duration-slow)]",
                          danger ? "bg-error" : warn ? "bg-warning" : "bg-brand"].join(" ")}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
          <p className="mt-5 text-[length:var(--font-xs)] text-caption">
            30-day total: ↓ {formatBytes(totalIn)} · ↑ {formatBytes(totalOut)} — the usage
            window resets on quota reset.
          </p>
        </div>
      </div>

      {/* Traffic chart */}
      <div className="mt-4 rounded-[--radius-lg] border border-line-2 bg-surface-1 p-4 shadow-card">
        <h2 className="text-[length:var(--font-s)] font-semibold text-secondary">
          Traffic — last 30 days
        </h2>
        <div className="mt-3 h-[220px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chart} margin={{ top: 4, right: 4, bottom: 0, left: 0 }}>
              <defs>
                <linearGradient id="gDown" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--brand-primary)" stopOpacity={0.28} />
                  <stop offset="100%" stopColor="var(--brand-primary)" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="var(--border-1)" vertical={false} />
              <XAxis dataKey="day" tick={{ fontSize: 11, fill: "var(--text-caption)" }} tickLine={false} axisLine={{ stroke: "var(--border-2)" }} />
              <YAxis tick={{ fontSize: 11, fill: "var(--text-caption)" }} tickLine={false} axisLine={false} width={56} tickFormatter={(v: number) => formatBytes(v).replace(" ", "")} />
              <Tooltip
                formatter={(v: number | string, name: string) => [formatBytes(Number(v)), name === "down" ? "Download" : "Upload"]}
                labelStyle={{ color: "var(--text-primary)" }}
                contentStyle={{ background: "var(--surface-2)", border: "1px solid var(--border-2)", borderRadius: "var(--radius-sm)", fontSize: "12px", color: "var(--text-primary)" }}
              />
              <Area type="monotone" dataKey="down" stroke="var(--brand-primary)" strokeWidth={1.8} fill="url(#gDown)" />
              <Area type="monotone" dataKey="up" stroke="var(--success-500)" strokeWidth={1.8} fill="transparent" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Destinations */}
      <div className="mt-4">
        <h2 className="mb-3 text-[length:var(--font-s)] font-semibold text-secondary">
          Top destinations — 30 days
        </h2>
        <DataTable
          columns={destColumns}
          rows={analytics.data?.destinations ?? []}
          loading={analytics.loading}
          emptyLabel="No destination stats recorded"
          rowKey={(d) => `${d.host}:${d.port}:${d.protocol}`}
        />
      </div>

      {/* Current connections */}
      <div className="mt-6">
        <h2 className="mb-3 text-[length:var(--font-s)] font-semibold text-secondary">
          Current connections
        </h2>
        <DataTable
          columns={[
            { key: "time", header: "Time", render: (c) => <span className="text-secondary">{formatDateTime(c.time)}</span>, sortValue: (c) => c.time },
            { key: "host", header: "Destination", render: (c) => `${c.host}:${c.port}` },
            { key: "protocol", header: "Protocol", render: (c) => <span className="text-secondary">{c.protocol}</span> },
            { key: "client", header: "Client", render: (c) => <span className="text-secondary">{c.client_ip}</span> },
            { key: "blocked", header: "Status", render: (c) => c.blocked ? <Badge tone="error">blocked</Badge> : <Badge tone="success">ok</Badge> },
          ]}
          rows={connections}
          loading={live.loading}
          emptyLabel="No live connections for this user"
          rowKey={(c) => `${c.time}-${c.host}-${c.port}-${c.client_ip}`}
        />
      </div>

      {/* Recent activity */}
      <div className="mt-6">
        <h2 className="mb-3 text-[length:var(--font-s)] font-semibold text-secondary">
          Recent activity
        </h2>
        <DataTable
          columns={[
            { key: "time", header: "Time", render: (e) => <span className="text-secondary">{formatDateTime(e.timestamp)}</span>, sortValue: (e) => e.timestamp },
            { key: "action", header: "Action", render: (e) => e.action },
            { key: "result", header: "Result", render: (e) => e.result === "success" ? <Badge tone="success">ok</Badge> : <Badge tone="error">failure</Badge> },
            { key: "detail", header: "Detail", render: (e) => <span className="text-caption">{e.detail || "—"}</span> },
          ]}
          rows={auditRows}
          loading={audit.loading}
          emptyLabel="No recorded activity for this user"
          rowKey={(e) => e.id}
        />
        <p className="mt-2 text-[length:var(--font-xs)] text-caption">
          Full trail on <Link className="text-brand-text hover:underline" to="/logs">the Logs page</Link>.
        </p>
      </div>

      {editing && (
        <Modal open wide title={`Edit ${u.username}`} onClose={() => setEditing(false)}>
          <UserForm user={u} submitLabel="Save changes" onSubmit={onEdit} />
        </Modal>
      )}
    </>
  );
}

function StatusBadge({ status }: { status: string }) {
  const tone = status === "active" ? "success" : status === "disabled" ? "warning" : "error";
  return <Badge tone={tone}>{status}</Badge>;
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-3">
      <dt className="text-secondary">{label}</dt>
      <dd className="font-medium">{value}</dd>
    </div>
  );
}
