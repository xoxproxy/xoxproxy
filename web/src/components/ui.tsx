// Shared primitives, all sized off the design tokens (--control-*,
// --radius-control, --space-*, --button-*). Every interactive element
// keeps a visible focus ring.

export function Button({
  variant = "primary",
  size = "m",
  className = "",
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "elevated" | "ghost" | "danger";
  size?: "s" | "m";
}) {
  const base =
    "inline-flex items-center justify-center gap-2 rounded-[--radius-control] font-medium " +
    "transition-colors duration-[var(--duration)] ease-[var(--ease)] disabled:opacity-50 disabled:pointer-events-none";
  const variants = {
    primary:
      "bg-[var(--button-primary)] text-on-brand hover:bg-[var(--button-primary-hover)]",
    elevated:
      "bg-[var(--button-elevated)] text-primary border border-line-2 hover:bg-[var(--button-elevated-hover)]",
    ghost:
      "bg-[var(--button-ghost-fill)] text-brand-text border border-[var(--button-ghost-border)] hover:bg-[var(--button-ghost-hover)]",
    danger: "bg-error text-white hover:opacity-90",
  };
  const sizes = {
    s: "h-[var(--control-s)] px-3 text-[length:var(--font-s)]",
    m: "h-[var(--control-m)] px-4 text-[length:var(--font-sp)]",
  };
  return (
    <button
      className={[base, variants[variant], sizes[size], className].join(" ")}
      {...props}
    />
  );
}

export function IconButton({
  label,
  className = "",
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { label: string }) {
  return (
    <button
      aria-label={label}
      title={label}
      className={[
        "flex h-[var(--control-s)] w-[var(--control-s)] items-center justify-center",
        "rounded-[--radius-control] text-tertiary transition-colors duration-[var(--duration)]",
        "hover:bg-[var(--interactive-hover)] hover:text-primary disabled:opacity-50 disabled:pointer-events-none",
        className,
      ].join(" ")}
      {...props}
    />
  );
}

type Tone = "success" | "warning" | "error" | "info" | "neutral";

export function Badge({ tone = "neutral", children }: {
  tone?: Tone;
  children: React.ReactNode;
}) {
  const tones = {
    success: "bg-success-soft text-success",
    warning: "bg-warning-soft text-warning",
    error: "bg-error-soft text-error",
    info: "bg-info-soft text-info",
    neutral: "bg-[var(--interactive-hover)] text-secondary",
  };
  return (
    <span
      className={[
        "inline-flex h-[22px] items-center rounded-[--radius-pill] px-2",
        "text-[length:var(--font-xs)] font-semibold uppercase tracking-wide",
        tones[tone],
      ].join(" ")}
    >
      {children}
    </span>
  );
}

export function StatusDot({ tone }: { tone: Tone }) {
  const colors = {
    success: "bg-success",
    warning: "bg-warning",
    error: "bg-error",
    info: "bg-info",
    neutral: "bg-caption",
  };
  return (
    <span className="inline-block h-[7px] w-[7px] rounded-[--radius-circle] shrink-0" >
      <span className={["block h-full w-full", colors[tone]].join(" ")} />
    </span>
  );
}

export function PageHeader({ title, actions }: {
  title: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="mb-6 flex items-center justify-between gap-4">
      <h1 className="text-[length:var(--font-l)] font-semibold tracking-tight">
        {title}
      </h1>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

export function StatCard({ label, value, hint, tone }: {
  label: string;
  value: React.ReactNode;
  hint?: React.ReactNode;
  tone?: Tone;
}) {
  const dot = tone ? <StatusDot tone={tone} /> : null;
  return (
    <div className="rounded-[--radius-lg] border border-line-2 bg-surface-1 p-4 shadow-card">
      <div className="flex items-center gap-2 text-[length:var(--font-s)] text-secondary">
        {dot}
        {label}
      </div>
      <div className="mt-2 text-[22px] font-semibold leading-8 tracking-tight">
        {value}
      </div>
      {hint && (
        <div className="mt-1 text-[length:var(--font-xs)] text-caption">
          {hint}
        </div>
      )}
    </div>
  );
}

export function Modal({ open, title, onClose, children, wide }: {
  open: boolean;
  title: string;
  onClose: () => void;
  children: React.ReactNode;
  wide?: boolean;
}) {
  if (!open) return null;
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      aria-label={title}
    >
      <div className="absolute inset-0 bg-black/40" onClick={onClose} aria-hidden />
      <div
        className={[
          "relative max-h-[85vh] w-full overflow-y-auto rounded-[--radius-lg]",
          "border border-line-2 bg-surface-1 p-6 shadow-modal animate-fade-in",
          wide ? "max-w-[560px]" : "max-w-[420px]",
        ].join(" ")}
      >
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-[length:var(--font-m)] font-semibold">{title}</h2>
          <IconButton label="Close" onClick={onClose}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" aria-hidden>
              <path d="M6 6l12 12M18 6 6 18" stroke="currentColor"
                strokeWidth="2" strokeLinecap="round" />
            </svg>
          </IconButton>
        </div>
        {children}
      </div>
    </div>
  );
}

export function Tabs<T extends string>({ tabs, value, onChange }: {
  tabs: { key: T; label: string }[];
  value: T;
  onChange: (key: T) => void;
}) {
  return (
    <div
      className="inline-flex gap-1 rounded-[--radius-control] bg-[var(--interactive-hover)] p-1"
      role="tablist"
    >
      {tabs.map((t) => (
        <button
          key={t.key}
          role="tab"
          aria-selected={value === t.key}
          onClick={() => onChange(t.key)}
          className={[
            "h-[var(--control-s)] rounded-[--radius-xs] px-3 text-[length:var(--font-s)] font-medium",
            "transition-colors duration-[var(--duration)]",
            value === t.key
              ? "bg-surface-1 text-primary shadow-card"
              : "text-secondary hover:text-primary",
          ].join(" ")}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function Toggle({ checked, onChange, label }: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      onClick={() => onChange(!checked)}
      className={[
        "h-[20px] w-[36px] rounded-[--radius-pill] p-[2px] transition-colors duration-[var(--duration)]",
        checked ? "bg-brand" : "bg-line-3",
      ].join(" ")}
    >
      <span
        className={[
          "block h-[16px] w-[16px] rounded-[--radius-circle] bg-white shadow-card",
          "transition-transform duration-[var(--duration)] ease-[var(--ease)]",
          checked ? "translate-x-4" : "translate-x-0",
        ].join(" ")}
      />
    </button>
  );
}

export function FormInput({ label, hint, className = "", ...props }: {
  label: string;
  hint?: string;
} & React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <label className="block">
      <span className="mb-[6px] block text-[length:var(--font-s)] font-medium text-secondary">
        {label}
      </span>
      <input
        className={[
          "h-[var(--control-l)] w-full rounded-[--radius-control] border border-line-2 bg-background px-3",
          "text-primary outline-none transition-colors duration-[var(--duration)]",
          "placeholder:text-caption focus-visible:border-brand",
          className,
        ].join(" ")}
        {...props}
      />
      {hint && (
        <span className="mt-1 block text-[length:var(--font-xs)] text-caption">
          {hint}
        </span>
      )}
    </label>
  );
}

export function EmptyState({ label }: { label: string }) {
  return (
    <div className="flex flex-col items-center gap-2 py-12 text-center">
      <div className="flex h-10 w-10 items-center justify-center rounded-[--radius-circle] bg-[var(--interactive-hover)] text-caption">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden>
          <path d="M4 7h16M4 12h16M4 17h10" stroke="currentColor"
            strokeWidth="1.8" strokeLinecap="round" />
        </svg>
      </div>
      <p className="text-[length:var(--font-s)] text-caption">{label}</p>
    </div>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-3 py-12 text-secondary">
      <div className="h-5 w-5 animate-spin rounded-[--radius-circle] border-2 border-line-3 border-t-brand" />
      {label && <span className="text-[length:var(--font-s)]">{label}</span>}
    </div>
  );
}

export function ErrorNote({ message }: { message: string }) {
  return (
    <p role="alert" className="text-[length:var(--font-s)] text-error">
      {message}
    </p>
  );
}
