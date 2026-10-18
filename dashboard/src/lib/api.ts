import type { BlocklistItem, CaseDetail, CaseSummary, DemoMeta, EvalReport, Indicator, Overview, RuleInfo, Verdict } from "./types";
import { setClock } from "./format";

export type Mode = "demo" | "live";

const TOKEN_KEY = "unhook.token";
export const getToken = () => { try { return sessionStorage.getItem(TOKEN_KEY) ?? ""; } catch { return ""; } };
export const setToken = (t: string) => { try { sessionStorage.setItem(TOKEN_KEY, t); } catch { /* private mode */ } };

export class AuthError extends Error {}

let mode: Mode = "demo";
export const currentMode = () => mode;

// Live if the API answers /healthz, demo otherwise. VITE_MODE can force either.
export async function detectMode(): Promise<Mode> {
  const forced = import.meta.env.VITE_MODE;
  if (forced === "demo" || forced === "live") {
    mode = forced;
  } else {
    try {
      const r = await fetch("/healthz", { cache: "no-store" });
      const json = r.ok && (r.headers.get("content-type") ?? "").includes("json") ? await r.json() : null;
      mode = json?.ok ? "live" : "demo";
    } catch {
      mode = "demo";
    }
  }
  if (mode === "demo") {
    const meta = await demo<DemoMeta>("meta.json");
    setClock(meta.generated_at);
  }
  return mode;
}

const demoCache = new Map<string, Promise<unknown>>();
function demo<T>(file: string): Promise<T> {
  if (!demoCache.has(file)) {
    const p = fetch(`${import.meta.env.BASE_URL}demo/${file}`).then((r) => {
      if (!r.ok) throw new Error(`demo data missing: ${file}`);
      return file.endsWith(".txt") ? r.text() : r.json();
    });
    p.catch(() => demoCache.delete(file));
    demoCache.set(file, p);
  }
  return demoCache.get(file) as Promise<T>;
}

async function live<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getToken();
  const headers = new Headers(init?.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const r = await fetch(path, { ...init, headers });
  if (r.status === 401) throw new AuthError("This server needs an API token.");
  if (!r.ok) {
    const detail = await r.json().then((j) => j.detail).catch(() => r.statusText);
    throw new Error(typeof detail === "string" ? detail : r.statusText);
  }
  const type = r.headers.get("content-type") ?? "";
  return (type.includes("json") ? r.json() : r.text()) as Promise<T>;
}

// In demo mode, analyst actions only live in memory. Reloading puts everything back.
type Patch = Partial<Pick<CaseDetail, "status" | "resolution" | "assignee" | "analyst_minutes">>;
const overlay = new Map<string, Patch>();
const withOverlay = <T extends CaseSummary>(c: T): T => ({ ...c, ...(overlay.get(c.id) ?? {}) });

export const api = {
  overview: () => (mode === "live" ? live<Overview>("/api/stats/overview") : demo<Overview>("overview.json")),

  cases: async (): Promise<CaseSummary[]> => {
    if (mode === "live") return (await live<{ items: CaseSummary[] }>("/api/cases?limit=500")).items;
    return (await demo<{ items: CaseSummary[] }>("cases.json")).items.map(withOverlay);
  },

  caseDetail: async (id: string): Promise<CaseDetail> => {
    if (mode === "live") return live<CaseDetail>(`/api/cases/${id}`);
    return withOverlay(await demo<CaseDetail>(`cases/${id}.json`));
  },

  updateCase: async (id: string, patch: Patch): Promise<CaseDetail> => {
    if (mode === "live") {
      return live<CaseDetail>(`/api/cases/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(patch),
      });
    }
    const next: Patch = { ...patch };
    if (patch.resolution) next.status = "resolved";
    overlay.set(id, { ...(overlay.get(id) ?? {}), ...next });
    return api.caseDetail(id);
  },

  rules: () => (mode === "live" ? live<RuleInfo[]>("/api/rules") : demo<RuleInfo[]>("rules.json")),
  evaluation: () => (mode === "live" ? live<EvalReport>("/api/eval/latest") : demo<EvalReport>("eval.json")),
  indicators: () => (mode === "live" ? live<Indicator[]>("/api/indicators") : demo<Indicator[]>("indicators.json")),

  blocklist: async (): Promise<BlocklistItem[]> => {
    if (mode === "demo") return demo<BlocklistItem[]>("blocklist.json");
    return (JSON.parse(await live<string>("/api/blocklist/json")) as { indicators: BlocklistItem[] }).indicators;
  },

  // The feed URL a firewall or resolver would poll. Only meaningful against a live server.
  blocklistUrl: (fmt: "txt" | "rpz" | "csv" | "json") => {
    const token = getToken();
    return `/api/blocklist/${fmt}${token ? `?token=${encodeURIComponent(token)}` : ""}`;
  },

  async submitReport(file: File, reporter: string): Promise<{ id: string }> {
    const form = new FormData();
    form.append("file", file);
    form.append("reporter", reporter);
    return live<{ id: string }>("/api/reports", { method: "POST", body: form });
  },

  report: (id: string) =>
    live<{ status: string; verdict?: Verdict; message?: string; case?: string; seconds_to_verdict?: number; error?: string }>(`/api/reports/${id}`),
};
