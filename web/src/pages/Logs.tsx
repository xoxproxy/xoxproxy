import { useMemo, useState } from "react";
import { AuditEntry } from "../api/client";
import DataTable, { Column } from "../components/DataTable";
import { Badge, Button, PageHeader, Tabs } from "../components/ui";
import { useApi, useInterval } from "../lib/hooks";
import { formatDateTime } from "../lib/format";

type Tab = "audit" | "engine";
const AUDIT_PAGE = 50;

// Logs: audit trail (cursor-paginated, action filter) and the engine
// traffic-log tail. Application/system logs stay in journald — out of
// scope for the dashboard (README notes this).
export default function Logs() {
  const [tab, setTab] = useState<Tab>("audit");
  const [action, setAction] = useState("");
  const [beforeId, setBeforeId] = useState<number | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const query = useMemo(() => {
    const params = new URLSearchParams({ limit: String(AUDIT_PAGE) });
    if (action) params.set("action", action);
    if (beforeId !== null) params.set("before_id", String(beforeId));
    return params.toString();
  }, [action, beforeId]);

  const audit = useApi<{ entries: AuditEntry[] }>(
    tab === "audit" ? `/api/v1/audit-logs?${query}` : null,
  );
  const engine = useApi<{ lines: string[] }>(
    tab === "engine" ? "/api/v1/logs/engine?limit=200" : null,
  );

  useInterval(() => {
    if (autoRefresh) {
      if (tab === "audit" && beforeId === null) audit.reload();
      if (tab === "engine") engine.reload();
    }
  }, 10_000);

  const entries = audit.data?.entries ?? [];
  const olderAvailable = entries.length === AUDIT_PAGE;

  const auditColumns: Column<AuditEntry>[] = [
    { key: "time", header: "Time", render: (e) => <span className="text-secondary">{formatDateTime(e.timestamp)}</span>, sortValue: (e) => e.timestamp },
    { key: "actor", header: "Actor", render: (e) => e.actor },
    { key: "action", header: "Action", render: (e) => <span className="font-mono text-[length:var(--font-s)]">{e.action}</span>, sortValue: (e) => e.action },
    { key: "target", header: "Target", render: (e) => e.target || <span className="text-caption">—</span> },
    { key: "result", header: "Result", render: (e) => e.result === "success" ? <Badge tone="success">ok</Badge> : <Badge tone="error">failure</Badge> },
    { key: "source", header: "Source", render: (e) => <span className="text-secondary">{e.source_ip}</span> },
    { key: "detail", header: "Detail", render: (e) => <span className="text-caption">{e.detail || "—"}</span> },
  ];

  return (
    <>
      <PageHeader
        title="Logs"
        actions={
          <Tabs
            tabs={[
              { key: "audit", label: "Audit trail" },
              { key: "engine", label: "Proxy log" },
            ]}
            value={tab}
            onChange={setTab}
          />
        }
      />

      {tab === "audit" && (
        <>
          <div className="mb-4 flex flex-wrap items-center gap-3">
            <input
              type="search"
              placeholder="Filter by action — e.g. user.create"
              value={action}
              onChange={(e) => { setAction(e.target.value); setBeforeId(null); }}
              className="h-[var(--control-m)] w-64 rounded-[--radius-control] border border-line-2 bg-background px-3 text-[length:var(--font-s)] text-primary outline-none transition-colors duration-[var(--duration)] placeholder:text-caption focus-visible:border-brand"
            />
            {beforeId !== null && (
              <Button variant="elevated" size="s" onClick={() => setBeforeId(null)}>
                ← Latest
              </Button>
            )}
            <label className="ml-auto flex items-center gap-2 text-[length:var(--font-s)] text-secondary">
              <input
                type="checkbox"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
                className="h-[14px] w-[14px] accent-[var(--brand-primary)]"
              />
              Auto-refresh
            </label>
          </div>

          <DataTable
            columns={auditColumns}
            rows={entries}
            loading={audit.loading}
            emptyLabel={action ? `No entries for ${action}` : "No audit entries"}
            rowKey={(e) => e.id}
          />

          {olderAvailable && (
            <div className="mt-4 flex justify-center">
              <Button
                variant="elevated"
                size="s"
                onClick={() => setBeforeId(entries[entries.length - 1].id)}
              >
                Older →
              </Button>
            </div>
          )}
        </>
      )}

      {tab === "engine" && (
        <div className="overflow-hidden rounded-[--radius-lg] border border-line-2 bg-surface-1 shadow-card">
          {engine.loading ? (
            <p className="p-4 text-[length:var(--font-s)] text-caption">Loading…</p>
          ) : (engine.data?.lines ?? []).length === 0 ? (
            <p className="p-4 text-[length:var(--font-s)] text-caption">
              No traffic log available (engine not running or logging disabled).
            </p>
          ) : (
            <pre className="max-h-[560px] overflow-auto bg-[var(--code-background)] p-4 font-mono text-[length:var(--font-s)] leading-[1.6] text-primary">
              {(engine.data?.lines ?? []).join("\n")}
            </pre>
          )}
        </div>
      )}
    </>
  );
}
