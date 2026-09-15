import { useState } from "react";
import { api } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { Button, FormInput, PageHeader } from "../components/ui";

export default function Settings() {
  const { username } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (next !== confirm) {
      setError("The new passwords don't match.");
      return;
    }
    setBusy(true);
    try {
      await api.post("/api/v1/auth/password", {
        current_password: current,
        new_password: next,
      });
      setDone(true);
      setCurrent("");
      setNext("");
      setConfirm("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "password change failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHeader title="Settings" />

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-[--radius-lg] border border-line-2 bg-surface-1 p-5 shadow-card">
          <h2 className="text-[length:var(--font-m)] font-semibold">Account</h2>
          <dl className="mt-4 space-y-[10px] text-[length:var(--font-s)]">
            <div className="flex justify-between">
              <dt className="text-secondary">Username</dt>
              <dd className="font-medium">{username ?? "—"}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-secondary">Role</dt>
              <dd className="font-medium">admin</dd>
            </div>
          </dl>
          <p className="mt-4 text-[length:var(--font-xs)] text-caption">
            Changing the password revokes all other sessions.
          </p>
        </div>

        <form
          onSubmit={submit}
          className="rounded-[--radius-lg] border border-line-2 bg-surface-1 p-5 shadow-card"
        >
          <h2 className="text-[length:var(--font-m)] font-semibold">Change password</h2>
          <div className="mt-4 space-y-4">
            <FormInput
              label="Current password"
              type="password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
              autoComplete="current-password"
              required
            />
            <FormInput
              label="New password"
              type="password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
              autoComplete="new-password"
              minLength={12}
              required
              hint="At least 12 characters"
            />
            <FormInput
              label="Confirm new password"
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              autoComplete="new-password"
              required
            />
          </div>
          {error && (
            <p role="alert" className="mt-3 text-[length:var(--font-s)] text-error">{error}</p>
          )}
          {done && !error && (
            <p className="mt-3 text-[length:var(--font-s)] text-success">
              Password changed. Other sessions were signed out.
            </p>
          )}
          <div className="mt-5 flex justify-end">
            <Button type="submit" disabled={busy}>
              {busy ? "Changing…" : "Change password"}
            </Button>
          </div>
        </form>
      </div>
    </>
  );
}
