import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, NewCredential, ProxyUser } from "../api/client";
import DataTable, { Column } from "../components/DataTable";
import { Badge, Button, IconButton, Modal, PageHeader } from "../components/ui";
import UserForm, { UserFormValues } from "../components/UserForm";
import { useApi } from "../lib/hooks";
import { expiryDays, formatBitrate, formatRelative } from "../lib/format";

export default function Users() {
  const { data, loading, reload } = useApi<{ users: ProxyUser[] }>("/api/v1/users");
  const [statusFilter, setStatusFilter] = useState<"all" | "active" | "disabled" | "expired">("all");
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<ProxyUser | null>(null);
  const [credential, setCredential] = useState<NewCredential | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<ProxyUser | null>(null);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const users = data?.users ?? [];
  const filtered = useMemo(
    () => (statusFilter === "all" ? users : users.filter((u) => u.status === statusFilter)),
    [users, statusFilter],
  );

  const act = async (fn: () => Promise<unknown>) => {
    setError(null);
    try {
      await fn();
      reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "action failed");
    }
  };

  const onCreate = async (values: UserFormValues) => {
    const cred = await api.post<NewCredential>("/api/v1/users", values);
    setCreating(false);
    setCredential(cred); // one-time password modal
    reload();
  };

  const onEdit = async (values: UserFormValues) => {
    if (!editing) return;
    try {
      await api.patch<ProxyUser>(`/api/v1/users/${editing.id}`, {
        ...values,
        version: editing.version,
      });
      setEditing(null);
      reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "update failed");
    }
  };

  const onRotate = async (u: ProxyUser) => {
    setError(null);
    try {
      const cred = await api.post<NewCredential>(`/api/v1/users/${u.id}/rotate-credentials`, {
        version: u.version,
      });
      setCredential(cred);
      reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "rotation failed");
    }
  };

  const columns: Column<ProxyUser>[] = [
    {
      key: "username",
      header: "Username",
      render: (u) => (
        <button
          className="font-medium text-primary hover:text-brand-text"
          onClick={(e) => { e.stopPropagation(); navigate(`/users/${u.id}`); }}
        >
          {u.username}
        </button>
      ),
      sortValue: (u) => u.username,
    },
    {
      key: "status",
      header: "Status",
      render: (u) => {
        const tone = u.status === "active" ? "success" : u.status === "disabled" ? "warning" : "error";
        return <Badge tone={tone}>{u.status}</Badge>;
      },
      sortValue: (u) => u.status,
    },
    {
      key: "protocols",
      header: "Protocols",
      render: (u) => (
        <span className="text-secondary">
          {u.allowed_protocols.map((p) => p.toUpperCase()).join(" · ")}
        </span>
      ),
    },
    {
      key: "bandwidth",
      header: "Bandwidth",
      render: (u) => (
        <span className="tabular-nums text-secondary">
          {u.download_limit_bps || u.upload_limit_bps
            ? `${u.download_limit_bps ? "↓" + formatBitrate(u.download_limit_bps) : ""}${u.download_limit_bps && u.upload_limit_bps ? " " : ""}${u.upload_limit_bps ? "↑" + formatBitrate(u.upload_limit_bps) : ""}`
            : "∞"}
        </span>
      ),
      sortValue: (u) => u.download_limit_bps + u.upload_limit_bps,
      align: "right",
    },
    {
      key: "traffic",
      header: "Traffic",
      render: (u) => (
        <span className="tabular-nums text-secondary">
          {u.quota_bytes_daily || u.quota_bytes_monthly ? "quota set" : "∞"}
        </span>
      ),
      align: "right",
    },
    {
      key: "connections",
      header: "Connections",
      render: (u) => <span className="tabular-nums text-secondary">{u.max_connections || "∞"}</span>,
      sortValue: (u) => u.max_connections,
      align: "right",
    },
    {
      key: "expiration",
      header: "Expiration",
      render: (u) => {
        const days = expiryDays(u.expires_at);
        if (days === null) return <span className="text-caption">never</span>;
        const soon = days <= 7;
        return (
          <span className={["tabular-nums", soon ? "text-warning" : "text-secondary"].join(" ")}>
            {days < 0 ? `expired ${-days}d` : `${days}d left`}
          </span>
        );
      },
      sortValue: (u) => expiryDays(u.expires_at) ?? Number.MAX_SAFE_INTEGER,
    },
    {
      key: "last_seen",
      header: "Last Seen",
      render: (u) => <span className="text-secondary">{formatRelative(u.last_seen_at)}</span>,
      sortValue: (u) => u.last_seen_at ?? "",
    },
    {
      key: "actions",
      header: "Actions",
      render: (u) => (
        <div className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()}>
          <IconButton label="Edit" onClick={() => setEditing(u)}>
            <IconPencil />
          </IconButton>
          {u.status === "active" ? (
            <IconButton label="Disable" onClick={() => act(() => api.post(`/api/v1/users/${u.id}/disable`, { version: u.version }))}>
              <IconPause />
            </IconButton>
          ) : (
            <IconButton label="Enable" onClick={() => act(() => api.post(`/api/v1/users/${u.id}/enable`, { version: u.version }))}>
              <IconPlay />
            </IconButton>
          )}
          <IconButton label="Rotate credentials" onClick={() => onRotate(u)}>
            <IconKey />
          </IconButton>
          <IconButton label="Reset quota" onClick={() => act(() => api.post(`/api/v1/users/${u.id}/reset-quota`, { version: u.version }))}>
            <IconGauge />
          </IconButton>
          <IconButton label="Delete" className="hover:text-error" onClick={() => setConfirmDelete(u)}>
            <IconTrash />
          </IconButton>
        </div>
      ),
      align: "right",
    },
  ];

  return (
    <>
      <PageHeader
        title="Users"
        actions={
          <>
            {(["all", "active", "disabled", "expired"] as const).map((s) => (
              <button
                key={s}
                onClick={() => setStatusFilter(s)}
                className={[
                  "h-[var(--control-m)] rounded-[--radius-control] px-3 text-[length:var(--font-s)] font-medium capitalize",
                  "transition-colors duration-[var(--duration)]",
                  statusFilter === s
                    ? "bg-[var(--interactive-accent-hover)] text-primary"
                    : "text-secondary hover:bg-[var(--interactive-hover)]",
                ].join(" ")}
              >
                {s}
              </button>
            ))}
            <Button onClick={() => setCreating(true)}>+ New user</Button>
          </>
        }
      />

      {error && (
        <p role="alert" className="mb-4 text-[length:var(--font-s)] text-error">{error}</p>
      )}

      <DataTable
        columns={columns}
        rows={filtered}
        loading={loading}
        emptyLabel={statusFilter === "all" ? "No proxy users yet" : `No ${statusFilter} users`}
        onRowClick={(u) => navigate(`/users/${u.id}`)}
        rowKey={(u) => u.id}
      />

      {creating && (
        <UserFormModal title="New user" onClose={() => setCreating(false)} onSubmit={onCreate} submitLabel="Create user" />
      )}
      {editing && (
        <UserFormModal title={`Edit ${editing.username}`} user={editing} onClose={() => setEditing(null)} onSubmit={onEdit} submitLabel="Save changes" />
      )}

      {credential && (
        <CredentialModal cred={credential} onClose={() => setCredential(null)} />
      )}

      {confirmDelete && (
        <Modal open title={`Delete ${confirmDelete.username}?`} onClose={() => setConfirmDelete(null)}>
          <p className="text-[length:var(--font-s)] text-secondary">
            The user is removed from the engine config and their traffic
            history is kept for audit. This cannot be undone.
          </p>
          <div className="mt-5 flex justify-end gap-2">
            <Button variant="elevated" onClick={() => setConfirmDelete(null)}>Cancel</Button>
            <Button variant="danger" onClick={() => {
              const u = confirmDelete;
              setConfirmDelete(null);
              act(() => api.del(`/api/v1/users/${u.id}`, { version: u.version }));
            }}>
              Delete
            </Button>
          </div>
        </Modal>
      )}
    </>
  );
}

function UserFormModal({ title, user, onClose, onSubmit, submitLabel }: {
  title: string;
  user?: ProxyUser;
  onClose: () => void;
  onSubmit: (values: UserFormValues) => Promise<void>;
  submitLabel: string;
}) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <Modal open wide title={title} onClose={onClose}>
      <UserForm
        user={user}
        submitLabel={submitLabel}
        onSubmit={async (values) => {
          setBusy(true);
          setError(null);
          try {
            await onSubmit(values);
          } catch (err) {
            setError(err instanceof Error ? err.message : "failed");
          } finally {
            setBusy(false);
          }
        }}
      />
      {error && <p role="alert" className="mt-3 text-[length:var(--font-s)] text-error">{error}</p>}
      {busy && <p className="mt-3 text-[length:var(--font-s)] text-caption">Working…</p>}
    </Modal>
  );
}

function CredentialModal({ cred, onClose }: { cred: NewCredential; onClose: () => void }) {
  const [copied, setCopied] = useState<string | null>(null);
  const httpUrl = `http://${cred.username}:${cred.password}@${location.hostname}:3128`;
  const socksUrl = `socks5://${cred.username}:${cred.password}@${location.hostname}:1080`;

  const copy = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      // Clipboard API unavailable ( insecure context ): the value is
      // selectable text, so manual copy still works.
    }
  };

  return (
    <Modal open title={`Credentials for ${cred.username}`} onClose={onClose}>
      <p className="text-[length:var(--font-s)] text-secondary">
        This password is shown <strong>once</strong>. Copy it now — it cannot
        be recovered.
      </p>
      <div className="mt-4 space-y-3">
        <div>
          <span className="mb-1 block text-[length:var(--font-xs)] font-semibold uppercase tracking-wide text-caption">
            Password
          </span>
          <code className="block break-all rounded-[--radius-sm] border border-line-2 bg-[var(--code-background)] px-3 py-2 font-mono text-[length:var(--font-s)] text-primary">
            {cred.password}
          </code>
        </div>
        {[
          { key: "http", label: "HTTP proxy URL", url: httpUrl, port: 3128 },
          { key: "socks", label: "SOCKS5 proxy URL", url: socksUrl, port: 1080 },
        ].map((item) => (
          <div key={item.key}>
            <span className="mb-1 block text-[length:var(--font-xs)] font-semibold uppercase tracking-wide text-caption">
              {item.label}
            </span>
            <div className="flex gap-2">
              <code className="min-w-0 flex-1 break-all rounded-[--radius-sm] border border-line-2 bg-[var(--code-background)] px-3 py-2 font-mono text-[length:var(--font-s)] text-primary">
                {item.url}
              </code>
              <Button variant="ghost" size="s" onClick={() => copy(item.url, item.key)}>
                {copied === item.key ? "Copied" : "Copy"}
              </Button>
            </div>
          </div>
        ))}
      </div>
      <div className="mt-5 flex justify-end">
        <Button onClick={onClose}>Done</Button>
      </div>
    </Modal>
  );
}

// --- tiny inline icons (kept local; they're page-specific) ---

const svg = (d: string) => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden>
    <path d={d} stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);
const IconPencil = () => svg("M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5Z");
const IconPause = () => svg("M9 5v14M15 5v14");
const IconPlay = () => svg("M7 5l12 7-12 7V5Z");
const IconKey = () => svg("M21 2l-9.6 9.6M15.5 7.5l3 3L22 7l-3-3M11 13a7 7 0 1 1-7 7 7 7 0 0 1 7-7Z");
const IconGauge = () => svg("M12 15l3.5-3.5M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z");
const IconTrash = () => svg("M3 6h18M8 6V4h8v2m-9 0 1 14h8l1-14");
