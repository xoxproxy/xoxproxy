import { useEffect, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";

interface NavItem {
  to: string;
  label: string;
  icon: React.ReactNode;
}

const icon = (d: string) => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden>
    <path d={d} stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"
      strokeLinejoin="round" />
  </svg>
);

const NAV: NavItem[] = [
  {
    to: "/",
    label: "Overview",
    icon: icon("M4 13h6V4H4v9Zm0 7h6v-4H4v4Zm10 0h6V11h-6v9Zm0-16v4h6V4h-6Z"),
  },
  {
    to: "/users",
    label: "Users",
    icon: icon("M16 20v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M9 10a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm13 10v-2a4 4 0 0 0-3-3.87M16 3.13A4 4 0 0 1 16 11"),
  },
  {
    to: "/analytics",
    label: "Analytics",
    icon: icon("M3 3v18h18M7 15l3.5-3.5 3 3L19 9"),
  },
  {
    to: "/server",
    label: "Server",
    icon: icon("M8 3v3m8-3v3M4 9h16M5 5h14a1 1 0 0 1 1 1v13a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1Zm4 9h.01M12 14h.01M16 14h.01M9 17h.01M12 17h.01M16 17h.01"),
  },
  {
    to: "/logs",
    label: "Logs",
    icon: icon("M6 3h9l5 5v13a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Zm9 0v5h5M9 13h6M9 17h6M9 9h2"),
  },
  {
    to: "/settings",
    label: "Settings",
    icon: icon("M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm7.4-3a7.4 7.4 0 0 0-.1-1.2l2-1.6-2-3.4-2.4 1a7.6 7.6 0 0 0-2-1.2L14.5 2h-4l-.4 2.6a7.6 7.6 0 0 0-2 1.2l-2.4-1-2 3.4 2 1.6a7.4 7.4 0 0 0 0 2.4l-2 1.6 2 3.4 2.4-1a7.6 7.6 0 0 0 2 1.2l.4 2.6h4l.4-2.6a7.6 7.6 0 0 0 2-1.2l2.4 1 2-3.4-2-1.6c.07-.4.1-.8.1-1.2Z"),
  },
];

function useTheme() {
  const [dark, setDark] = useState(() =>
    document.documentElement.classList.contains("dark"),
  );
  const toggle = () => {
    const next = !dark;
    setDark(next);
    document.documentElement.classList.toggle("dark", next);
    localStorage.setItem("xox-theme", next ? "dark" : "light");
  };
  return { dark, toggle };
}

function Sidebar({ open, collapsed, onClose }: {
  open: boolean;
  collapsed: boolean;
  onClose: () => void;
}) {
  return (
    <>
      {/* Mobile scrim */}
      {open && (
        <div
          className="fixed inset-0 z-30 bg-black/40 md:hidden"
          onClick={onClose}
          aria-hidden
        />
      )}
      <aside
        className={[
          "fixed inset-y-0 left-0 z-40 flex flex-col border-r border-line-2 bg-surface-1",
          "transition-[width,transform] duration-[var(--duration-slow)] ease-[var(--ease)]",
          collapsed ? "w-[68px]" : "w-[228px]",
          open ? "translate-x-0" : "-translate-x-full md:translate-x-0",
        ].join(" ")}
      >
        {/* Brand */}
        <div className="flex h-14 items-center gap-[10px] px-4">
          <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-[--radius-control] bg-brand text-on-brand">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" aria-hidden>
              <path d="M12 3v4m0 10v4m9-9h-4M7 12H3m12.7-6.7-2.8 2.8M11.1 11.1 8.3 8.3m7.6 7.4-2.8-2.8M11.1 12.9l-2.8 2.8"
                stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
            </svg>
          </div>
          {!collapsed && (
            <span className="text-[length:var(--font-m)] font-semibold tracking-tight">
              xoxproxy
            </span>
          )}
        </div>

        {/* Nav */}
        <nav className="mt-2 flex flex-1 flex-col gap-1 px-2">
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === "/"}
              onClick={onClose}
              title={collapsed ? item.label : undefined}
              className={({ isActive }) =>
                [
                  "flex h-[var(--control-l)] items-center gap-3 rounded-[--radius-control] px-3",
                  "text-[length:var(--font-sp)] transition-colors duration-[var(--duration)]",
                  isActive
                    ? "bg-[var(--interactive-accent-hover)] font-semibold text-brand-text"
                    : "text-secondary hover:bg-[var(--interactive-hover)] hover:text-primary",
                ].join(" ")
              }
            >
              <span className="shrink-0">{item.icon}</span>
              {!collapsed && <span>{item.label}</span>}
            </NavLink>
          ))}
        </nav>

        <div className="border-t border-line-1 p-2">
          {!collapsed && (
            <p className="px-3 pb-2 text-[length:var(--font-xs)] text-caption">
              v{__APP_VERSION__}
            </p>
          )}
        </div>
      </aside>
    </>
  );
}

function Topbar({ onMenu, onToggleCollapse }: {
  onMenu: () => void;
  onToggleCollapse: () => void;
}) {
  const { username, logout } = useAuth();
  const { dark, toggle } = useTheme();
  const [menuOpen, setMenuOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();

  // Close the account menu on any navigation.
  useEffect(() => setMenuOpen(false), [location]);

  return (
    <header className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b border-line-2 bg-surface-1/90 px-4 backdrop-blur md:px-6">
      <button
        onClick={onMenu}
        className="flex h-[var(--control-m)] w-[var(--control-m)] items-center justify-center rounded-[--radius-control] text-secondary hover:bg-[var(--interactive-hover)] md:hidden"
        aria-label="Open navigation"
      >
        {icon("M4 6h16M4 12h16M4 18h16")}
      </button>
      <button
        onClick={onToggleCollapse}
        className="hidden h-[var(--control-m)] w-[var(--control-m)] items-center justify-center rounded-[--radius-control] text-secondary hover:bg-[var(--interactive-hover)] md:flex"
        aria-label="Toggle sidebar"
      >
        {icon("M11 19l-7-7 7-7m8 14l-7-7 7-7")}
      </button>

      <div className="flex-1" />

      {/* Theme toggle */}
      <button
        onClick={toggle}
        className="flex h-[var(--control-m)] w-[var(--control-m)] items-center justify-center rounded-[--radius-control] text-secondary hover:bg-[var(--interactive-hover)]"
        aria-label={dark ? "Switch to light theme" : "Switch to dark theme"}
      >
        {dark
          ? icon("M12 3v2m0 14v2M5.6 5.6l1.4 1.4m10 10 1.4 1.4M3 12h2m14 0h2M5.6 18.4 7 17m10-10 1.4-1.4M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z")
          : icon("M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8Z")}
      </button>

      {/* Account */}
      <div className="relative">
        <button
          onClick={() => setMenuOpen((v) => !v)}
          className="flex h-[var(--control-m)] items-center gap-2 rounded-[--radius-control] px-2 text-secondary hover:bg-[var(--interactive-hover)]"
          aria-haspopup="menu"
          aria-expanded={menuOpen}
        >
          <span className="flex h-7 w-7 items-center justify-center rounded-[--radius-pill] bg-brand text-[length:var(--font-s)] font-semibold text-on-brand">
            {(username ?? "?").slice(0, 1).toUpperCase()}
          </span>
          <span className="hidden text-[length:var(--font-sp)] font-medium text-primary sm:block">
            {username ?? ""}
          </span>
        </button>

        {menuOpen && (
          <>
            <div className="fixed inset-0 z-10" onClick={() => setMenuOpen(false)} aria-hidden />
            <div
              role="menu"
              className="absolute right-0 z-20 mt-2 w-44 overflow-hidden rounded-[--radius-md] border border-line-2 bg-surface-1 py-1 shadow-modal animate-fade-in"
            >
              <button
                onClick={() => { setMenuOpen(false); navigate("/settings"); }}
                className="flex h-[var(--control-m)] items-center px-3 text-[length:var(--font-sp)] text-secondary hover:bg-[var(--interactive-hover)] hover:text-primary"
                role="menuitem"
              >
                Settings
              </button>
              <button
                onClick={() => { setMenuOpen(false); logout().then(() => navigate("/login")); }}
                className="flex h-[var(--control-m)] w-full items-center px-3 text-[length:var(--font-sp)] text-error hover:bg-[var(--interactive-danger-hover)]"
                role="menuitem"
              >
                Sign out
              </button>
            </div>
          </>
        )}
      </div>
    </header>
  );
}

export default function Layout() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem("xox-sidebar") === "collapsed",
  );

  const toggleCollapse = () => {
    setCollapsed((v) => {
      localStorage.setItem("xox-sidebar", v ? "expanded" : "collapsed");
      return !v;
    });
  };

  return (
    <div className="min-h-screen bg-background">
      <Sidebar
        open={mobileOpen}
        collapsed={collapsed}
        onClose={() => setMobileOpen(false)}
      />
      <div
        className={[
          "flex min-h-screen flex-col transition-[padding] duration-[var(--duration-slow)] ease-[var(--ease)]",
          collapsed ? "md:pl-[68px]" : "md:pl-[228px]",
        ].join(" ")}
      >
        <Topbar onMenu={() => setMobileOpen(true)} onToggleCollapse={toggleCollapse} />
        <main className="mx-auto w-full max-w-[1200px] flex-1 px-4 py-6 md:px-6 md:py-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
