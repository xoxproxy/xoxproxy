import { Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth/AuthContext";
import Login from "./pages/Login";
import Layout from "./components/Layout";

import Overview from "./pages/Overview";
import Users from "./pages/Users";
import UserDetail from "./pages/UserDetail";
import Analytics from "./pages/Analytics";
import Server from "./pages/Server";
import Logs from "./pages/Logs";
import Settings from "./pages/Settings";

function Protected({ children }: { children: React.ReactNode }) {
  const { username, loading } = useAuth();
  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="h-6 w-6 animate-spin rounded-[--radius-circle] border-2 border-line-3 border-t-brand" />
      </div>
    );
  }
  if (username === null) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
}

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/"
          element={
            <Protected>
              <Layout />
            </Protected>
          }
        >
          <Route index element={<Overview />} />
          <Route path="users" element={<Users />} />
          <Route path="users/:id" element={<UserDetail />} />
          <Route path="analytics" element={<Analytics />} />
          <Route path="server" element={<Server />} />
          <Route path="logs" element={<Logs />} />
          <Route path="settings" element={<Settings />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  );
}
