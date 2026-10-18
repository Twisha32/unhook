import type { BlocklistItem } from "./types";

export type Format = "txt" | "rpz" | "csv" | "json";

// Mirrors backend/unhook/response/blocklist.py, so the demo can offer the same downloads
// a live server would hand to a resolver or firewall.
export function renderBlocklist(items: BlocklistItem[], fmt: Format): string {
  const stamp = new Date().toISOString().replace(/\.\d+Z$/, "Z");
  const domains = [...new Set(items.filter((i) => i.kind === "domain").map((i) => i.value))].sort();
  if (fmt === "txt") return `# Unhook domain blocklist, generated ${stamp}\n${domains.join("\n")}\n`;
  if (fmt === "rpz") {
    const head = [`; Unhook response policy zone, generated ${stamp}`, "$TTL 300", "@ IN SOA localhost. root.localhost. (1 1h 15m 30d 1h)", "  IN NS localhost."];
    return [...head, ...domains.map((d) => `${d} CNAME .`), ...domains.map((d) => `*.${d} CNAME .`)].join("\n") + "\n";
  }
  if (fmt === "csv") {
    const esc = (v: string) => (/[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
    const rows = [...items].sort((a, b) => a.kind.localeCompare(b.kind) || a.value.localeCompare(b.value));
    return ["kind,value,reason,case,added", ...rows.map((i) => [i.kind, i.value, i.reason, i.case, i.added].map(esc).join(","))].join("\n") + "\n";
  }
  return JSON.stringify({ generated: stamp, indicators: items }, null, 2);
}

export function download(name: string, body: string, type = "text/plain") {
  const url = URL.createObjectURL(new Blob([body], { type }));
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  document.body.append(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
