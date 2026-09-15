import { useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { api, ApiError, setCsrfToken } from "../api/client";

interface LoginResponse {
  username: string;
  csrf_token: string;
  expires_at: string;
}

export default function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const resp = await api.post<LoginResponse>("/api/v1/auth/login", {
        username,
        password,
      });
      setCsrfToken(resp.csrf_token);
      const params = new URLSearchParams(location.search);
      const next = params.get("next");
      navigate(next && next.startsWith("/") ? next : "/", { replace: true });
    } catch (err) {
      // Uniform message: no credential oracle in the UI either.
      setError(err instanceof ApiError && err.status === 401
        ? "Invalid username or password."
        : "Sign-in failed. Check the server and try again.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-6">
      <div className="w-full max-w-[380px]">
        <div className="mb-9 flex flex-col items-center gap-3">
          <div className="flex h-12 w-12 items-center justify-center rounded-[--radius-control] bg-brand text-on-brand shadow-card">
            {/* mark */}
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" aria-hidden>
              <path d="M12 3v4m0 10v4m9-9h-4M7 12H3m12.7-6.7-2.8 2.8M11.1 11.1 8.3 8.3m7.6 7.4-2.8-2.8M11.1 12.9l-2.8 2.8"
                stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
            </svg>
          </div>
          <div className="text-center">
            <h1 className="text-[length:var(--font-l)] font-semibold tracking-tight">
              xoxproxy
            </h1>
            <p className="mt-1 text-[length:var(--font-s)] text-secondary">
              Proxy management console
            </p>
          </div>
        </div>

        <form
          onSubmit={onSubmit}
          className="rounded-[--radius-lg] border border-line-2 bg-surface-1 p-7 shadow-modal"
        >
          <label className="block">
            <span className="mb-[6px] block text-[length:var(--font-s)] font-medium text-secondary">
              Username
            </span>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              autoFocus
              required
              className="h-[var(--control-l)] w-full rounded-[--radius-control] border border-line-2 bg-background px-3 text-primary outline-none transition-colors duration-[var(--duration)] placeholder:text-caption focus-visible:border-brand"
            />
          </label>

          <label className="mt-5 block">
            <span className="mb-[6px] block text-[length:var(--font-s)] font-medium text-secondary">
              Password
            </span>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
              className="h-[var(--control-l)] w-full rounded-[--radius-control] border border-line-2 bg-background px-3 text-primary outline-none transition-colors duration-[var(--duration)] placeholder:text-caption focus-visible:border-brand"
            />
          </label>

          {error && (
            <p role="alert" className="mt-4 text-[length:var(--font-s)] text-error">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={busy}
            className="mt-6 h-[var(--control-l)] w-full rounded-[--radius-control] bg-[var(--button-primary)] font-medium text-on-brand transition-colors duration-[var(--duration)] hover:bg-[var(--button-primary-hover)] disabled:opacity-60"
          >
            {busy ? "Signing in…" : "Sign in"}
          </button>
        </form>
      </div>
    </div>
  );
}
