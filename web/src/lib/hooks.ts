import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, subscribeStream, StreamTick } from "../api/client";

// useApi: fetch on mount (and whenever `path` changes), with loading and
// error state. For GET endpoints only.
export function useApi<T>(path: string | null): {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
} {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(path !== null);
  const [nonce, setNonce] = useState(0);
  const reload = useCallback(() => setNonce((n) => n + 1), []);

  useEffect(() => {
    if (path === null) return;
    let alive = true;
    setLoading(true);
    import("../api/client").then(({ api }) =>
      api.get<T>(path).then(
        (d) => {
          if (alive) { setData(d); setError(null); setLoading(false); }
        },
        (err) => {
          if (alive) {
            setError(err instanceof ApiError ? err.message : "request failed");
            setLoading(false);
          }
        },
      ),
    );
    return () => { alive = false; };
  }, [path, nonce]);

  return { data, error, loading, reload };
}

// useLiveStream: subscribes to the SSE tick stream while mounted.
// EventSource reconnects on its own for transient failures; the ready
// state is surfaced so the UI can show a "reconnecting" hint.
export function useLiveStream(): {
  tick: StreamTick | null;
  connected: boolean;
} {
  const [tick, setTick] = useState<StreamTick | null>(null);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const stop = subscribeStream((data) => {
      setConnected(true);
      setTick(data);
    });
    return stop;
  }, []);

  return { tick, connected };
}

// useInterval: setInterval with an always-fresh callback (no stale
// closures). Skips when the tab is hidden.
export function useInterval(cb: () => void, ms: number | null) {
  const ref = useRef(cb);
  ref.current = cb;
  useEffect(() => {
    if (ms === null) return;
    const id = setInterval(() => {
      if (!document.hidden) ref.current();
    }, ms);
    return () => clearInterval(id);
  }, [ms]);
}
