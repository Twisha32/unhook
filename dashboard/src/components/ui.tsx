import { useEffect, useRef, useState, type ReactNode } from "react";
import { AuthError, setToken } from "../lib/api";
import { VERDICT_LABEL } from "../lib/format";
import type { Verdict } from "../lib/types";
import { Icon } from "./Icons";

export function Panel({ title, hint, actions, children, className = "", pad = true }: {
  title?: ReactNode; hint?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; pad?: boolean;
}) {
  return (
    <section className={`panel ${className}`}>
      {(title || actions) && (
        <header className="panel-head">
          <div>
            {title && <h3>{title}</h3>}
            {hint && <p className="hint">{hint}</p>}
          </div>
          {actions && <div className="panel-actions">{actions}</div>}
        </header>
      )}
      <div className={pad ? "panel-body" : ""}>{children}</div>
    </section>
  );
}

export function VerdictBadge({ verdict, size = "md" }: { verdict: Verdict; size?: "sm" | "md" | "lg" }) {
  return (
    <span className={`badge badge-${size}`} data-v={verdict}>
      <i />
      {VERDICT_LABEL[verdict]}
    </span>
  );
}

export function StatusPill({ status }: { status: string }) {
  const label = { open: "Open", in_review: "In review", resolved: "Resolved", auto_closed: "Auto-closed" }[status] ?? status;
  return <span className="pill" data-status={status}>{label}</span>;
}

export function Chip({ children, tone = "neutral", title }: { children: ReactNode; tone?: "neutral" | "accent" | "danger" | "warn" | "ok"; title?: string }) {
  return <span className={`chip chip-${tone}`} title={title}>{children}</span>;
}

export function Segmented<T extends string>({ value, onChange, options, label }: {
  value: T; onChange: (v: T) => void; options: { value: T; label: string; count?: number }[]; label: string;
}) {
  return (
    <div className="seg" role="group" aria-label={label}>
      {options.map((o) => (
        <button key={o.value} type="button" aria-pressed={value === o.value} onClick={() => onChange(o.value)}>
          {o.label}
          {o.count !== undefined && <span className="seg-count">{o.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  const timer = useRef<number>(0);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const copy = async () => {
    try { await navigator.clipboard.writeText(text); } catch { return; }
    setDone(true);
    timer.current = window.setTimeout(() => setDone(false), 1400);
  };
  return (
    <button type="button" className="icon-btn" onClick={copy} title={done ? "Copied" : label} aria-label={label}>
      <Icon name={done ? "check" : "copy"} size={15} />
    </button>
  );
}

// Shows a defanged URL or host. The text is never an <a>, so nothing here can be clicked into a live phishing page.
export function Defanged({ value, max = 64 }: { value: string; max?: number }) {
  const shown = value.length > max ? `${value.slice(0, max - 1)}…` : value;
  return (
    <span className="defanged">
      <code title={value}>{shown}</code>
      <CopyButton text={value} label="Copy defanged" />
    </span>
  );
}

export function Skeleton({ h = 16, w = "100%", r = 8 }: { h?: number; w?: number | string; r?: number }) {
  return <span className="skeleton" style={{ height: h, width: w, borderRadius: r }} />;
}

export function PageSkeleton() {
  return (
    <div className="grid cols-4" aria-busy="true" aria-label="Loading">
      {[0, 1, 2, 3].map((i) => <div key={i} className="panel"><div className="panel-body"><Skeleton h={12} w="40%" /><div style={{ height: 14 }} /><Skeleton h={34} w="60%" /></div></div>)}
      <div className="panel span-3"><div className="panel-body"><Skeleton h={220} r={12} /></div></div>
      <div className="panel"><div className="panel-body"><Skeleton h={220} r={12} /></div></div>
    </div>
  );
}

export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      <div className="empty-mark"><Icon name="sparkle" size={22} /></div>
      <h3>{title}</h3>
      {children && <p>{children}</p>}
      {action}
    </div>
  );
}

function TokenForm({ retry }: { retry?: () => void }) {
  const [value, setValue] = useState("");
  return (
    <form className="token-form" onSubmit={(e) => { e.preventDefault(); setToken(value.trim()); retry?.(); }}>
      <input className="input" type="password" placeholder="API token" value={value} onChange={(e) => setValue(e.target.value)} autoFocus aria-label="API token" />
      <button className="btn btn-primary" type="submit" disabled={!value.trim()}>Unlock</button>
    </form>
  );
}

export function ErrorState({ error, retry }: { error: Error; retry?: () => void }) {
  if (error instanceof AuthError) {
    return <EmptyState title="This server needs a token" action={<TokenForm retry={retry} />}>Paste the API token you set in UNHOOK_API_TOKEN. It stays in this tab only.</EmptyState>;
  }
  return (
    <EmptyState title="Couldn't load this" action={retry && <button className="btn btn-ghost" onClick={retry}>Try again</button>}>
      {error.message}
    </EmptyState>
  );
}

export function Meter({ value, tone, thresholds }: { value: number; tone?: Verdict; thresholds?: { suspicious: number; malicious: number } }) {
  return (
    <div className="meter" data-v={tone}>
      <div className="meter-fill" style={{ width: `${Math.max(2, value * 100)}%` }} />
      {thresholds && (
        <>
          <i style={{ left: `${thresholds.suspicious * 100}%` }} title={`Suspicious from ${thresholds.suspicious}`} />
          <i style={{ left: `${thresholds.malicious * 100}%` }} title={`Malicious from ${thresholds.malicious}`} />
        </>
      )}
    </div>
  );
}

export function PageHeader({ title, sub, actions }: { title: ReactNode; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <header className="page-head">
      <div>
        <h1>{title}</h1>
        {sub && <p>{sub}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}
