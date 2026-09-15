import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { api, clearCsrfToken, setCsrfToken } from "../api/client";

export interface SessionInfo {
  username: string;
  csrf_token: string;
  expires_at: string;
}

interface AuthState {
  username: string | null;
  loading: boolean;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthState>({
  username: null,
  loading: true,
  refresh: async () => {},
  logout: async () => {},
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [username, setUsername] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const s = await api.get<SessionInfo>("/api/v1/auth/session");
      setCsrfToken(s.csrf_token);
      setUsername(s.username);
    } catch {
      setUsername(null);
    } finally {
      setLoading(false);
    }
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.post("/api/v1/auth/logout");
    } catch {
      // Logout is best-effort; the cookie is likely already gone.
    }
    clearCsrfToken();
    setUsername(null);
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return (
    <AuthContext.Provider value={{ username, loading, refresh, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
