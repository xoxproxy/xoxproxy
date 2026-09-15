import { useState } from "react";
import { ProxyUser } from "../api/client";
import { Button, FormInput, Toggle } from "./ui";

// UserForm: create + edit share one component. Values are plain strings;
// conversion happens on submit. Byte/bit inputs take human units (MB,
// Mbps) and convert to the API's raw numbers.
export interface UserFormValues {
  username: string;
  password?: string;
  allowed_protocols: string[];
  download_limit_bps: number;
  upload_limit_bps: number;
  max_connections: number;
  quota_bytes_daily: number;
  quota_bytes_monthly: number;
  expires_at: string | null;
}

const PROTOS = ["http", "socks5"] as const;

export default function UserForm({ user, submitLabel, onSubmit }: {
  user?: ProxyUser;
  submitLabel: string;
  onSubmit: (values: UserFormValues) => Promise<void>;
}) {
  const [username, setUsername] = useState(user?.username ?? "");
  const [password, setPassword] = useState("");
  const [protocols, setProtocols] = useState<string[]>(
    user?.allowed_protocols ?? ["http", "socks5"],
  );
  const [downMbps, setDownMbps] = useState(
    user && user.download_limit_bps ? String(user.download_limit_bps / 1_000_000) : "",
  );
  const [upMbps, setUpMbps] = useState(
    user && user.upload_limit_bps ? String(user.upload_limit_bps / 1_000_000) : "",
  );
  const [maxConn, setMaxConn] = useState(
    user?.max_connections ? String(user.max_connections) : "",
  );
  const [quotaDailyMB, setQuotaDailyMB] = useState(
    user && user.quota_bytes_daily ? String(Math.round(user.quota_bytes_daily / 1_000_000)) : "",
  );
  const [quotaMonthlyGB, setQuotaMonthlyGB] = useState(
    user && user.quota_bytes_monthly ? String(Math.round(user.quota_bytes_monthly / 1_000_000_000)) : "",
  );
  const [expires, setExpires] = useState(
    user?.expires_at ? user.expires_at.slice(0, 10) : "",
  );

  const toggleProto = (p: string) => {
    setProtocols((cur) =>
      cur.includes(p) ? cur.filter((x) => x !== p) : [...cur, p],
    );
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    await onSubmit({
      username: username.trim(),
      // Empty string → server generates a strong password.
      ...(user ? {} : { password: password || undefined }),
      allowed_protocols: protocols,
      download_limit_bps: downMbps ? Math.round(parseFloat(downMbps) * 1_000_000) : 0,
      upload_limit_bps: upMbps ? Math.round(parseFloat(upMbps) * 1_000_000) : 0,
      max_connections: maxConn ? parseInt(maxConn, 10) : 0,
      quota_bytes_daily: quotaDailyMB ? Math.round(parseFloat(quotaDailyMB) * 1_000_000) : 0,
      quota_bytes_monthly: quotaMonthlyGB
        ? Math.round(parseFloat(quotaMonthlyGB) * 1_000_000_000)
        : 0,
      expires_at: expires ? new Date(expires + "T23:59:59Z").toISOString() : null,
    });
  };

  return (
    <form onSubmit={submit} className="space-y-5">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <FormInput
          label="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          disabled={!!user}
          required
          pattern="[a-zA-Z0-9_.-]+"
          title="Letters, digits, dot, underscore, dash"
        />
        {!user && (
          <FormInput
            label="Password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            hint="Leave empty to generate"
            autoComplete="new-password"
          />
        )}
      </div>

      <div>
        <span className="mb-[6px] block text-[length:var(--font-s)] font-medium text-secondary">
          Protocols
        </span>
        <div className="flex gap-4">
          {PROTOS.map((p) => (
            <label key={p} className="flex items-center gap-2 text-[length:var(--font-sp)]">
              <Toggle
                checked={protocols.includes(p)}
                onChange={() => toggleProto(p)}
                label={p}
              />
              {p.toUpperCase()}
            </label>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <FormInput
          label="Download limit"
          inputMode="decimal"
          placeholder="unlimited"
          value={downMbps}
          onChange={(e) => setDownMbps(e.target.value)}
          hint="Mbps — empty = unlimited"
        />
        <FormInput
          label="Upload limit"
          inputMode="decimal"
          placeholder="unlimited"
          value={upMbps}
          onChange={(e) => setUpMbps(e.target.value)}
          hint="Mbps — empty = unlimited"
        />
        <FormInput
          label="Max connections"
          inputMode="numeric"
          placeholder="unlimited"
          value={maxConn}
          onChange={(e) => setMaxConn(e.target.value)}
          hint="Control-plane enforced"
        />
        <FormInput
          label="Expires"
          type="date"
          value={expires}
          onChange={(e) => setExpires(e.target.value)}
          hint="Empty = never expires"
        />
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <FormInput
          label="Daily quota"
          inputMode="decimal"
          placeholder="unlimited"
          value={quotaDailyMB}
          onChange={(e) => setQuotaDailyMB(e.target.value)}
          hint="MB"
        />
        <FormInput
          label="Monthly quota"
          inputMode="decimal"
          placeholder="unlimited"
          value={quotaMonthlyGB}
          onChange={(e) => setQuotaMonthlyGB(e.target.value)}
          hint="GB"
        />
      </div>

      <div className="flex justify-end">
        <Button type="submit">{submitLabel}</Button>
      </div>
    </form>
  );
}
