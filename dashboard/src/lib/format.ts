// "Now" is the moment the demo data was generated when we're showing demo data,
// so relative times still make sense when someone opens the demo months later.
let clock: number | null = null;
export const setClock = (iso: string | null) => { clock = iso ? Date.parse(iso) : null; };
export const now = () => clock ?? Date.now();

export const fmtInt = (n: number) => Math.round(n).toLocaleString("en-US");
export const fmtPct = (x: number, digits = 1) => `${(x * 100).toFixed(digits)}%`;
export const clamp = (x: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, x));

export function fmtMinutes(m: number): string {
  const sign = m < 0 ? "−" : "";
  const abs = Math.abs(m);
  if (abs >= 600) return `${sign}${(abs / 60).toFixed(abs >= 6000 ? 0 : 1)} h`;
  return `${sign}${Math.round(abs)} min`;
}

export function fmtSeconds(s: number): string {
  if (s < 1) return `${Math.max(1, Math.round(s * 1000))} ms`;
  if (s < 90) return `${s.toFixed(1)} s`;
  return `${Math.round(s / 60)} min`;
}

export function timeAgo(iso: string | null | undefined): string {
  if (!iso) return "never";
  const secs = Math.max(0, (now() - Date.parse(iso)) / 1000);
  if (secs < 60) return "just now";
  if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
  if (secs < 86400 * 14) return `${Math.floor(secs / 86400)}d ago`;
  return new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric" });
}

export function fmtDateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("en-US", { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export const VERDICT_LABEL: Record<string, string> = {
  malicious: "Malicious",
  suspicious: "Suspicious",
  likely_safe: "Likely safe",
};

export const STATUS_LABEL: Record<string, string> = {
  open: "Open",
  in_review: "In review",
  resolved: "Resolved",
  auto_closed: "Auto-closed",
};

export const GROUP_LABEL: Record<string, string> = {
  auth: "Sender authentication",
  identity: "Identity",
  domain: "Domain",
  url: "Links",
  attachment: "Attachments",
  content: "Wording",
  intel: "Threat intelligence",
};

// Values like "T1566.002" sort in a useful order as plain strings.
export const sortByCountDesc = <T extends { count: number }>(rows: T[]) => [...rows].sort((a, b) => b.count - a.count);

export const FLAG_LABEL: Record<string, string> = {
  active_html: "Active HTML",
  dangerous_extension: "Dangerous file type",
  deep_subdomains: "Deep subdomains",
  disguised_executable: "Disguised program",
  double_extension: "Double extension",
  encrypted_archive: "Encrypted archive",
  free_hosting: "Throwaway hosting",
  ip_host: "Raw IP address",
  macro_autoexec: "Auto-running macro",
  no_tls: "No HTTPS",
  odd_port: "Unusual port",
  pdf_active: "Active PDF",
  punycode: "Look-alike characters",
  risky_tld: "Risky TLD",
  shortener: "URL shortener",
  text_mismatch: "Text hides the real link",
  type_mismatch: "File type mismatch",
  userinfo: "Credentials in URL",
  very_long: "Very long URL",
};

export const defangHost = (host: string) => host.replace(/\./g, "[.]");
