import { useEffect, useMemo, useState } from "react";
import { Icon } from "../components/Icons";
import { Chip, EmptyState, ErrorState, Meter, PageHeader, PageSkeleton, Panel, Segmented, StatusPill, VerdictBadge } from "../components/ui";
import { api } from "../lib/api";
import { timeAgo } from "../lib/format";
import { go, useAsync } from "../lib/hooks";
import type { CaseStatus, CaseSummary, Verdict } from "../lib/types";

type VerdictFilter = Verdict | "all";
type StatusFilter = CaseStatus | "all" | "active";
type Sort = "newest" | "score" | "reports";

const PAGE = 40;

export function Queue({ query }: { query: URLSearchParams }) {
  const cases = useAsync(() => api.cases(), []);
  const [verdict, setVerdict] = useState<VerdictFilter>((query.get("verdict") as VerdictFilter) || "all");
  const [status, setStatus] = useState<StatusFilter>((query.get("status") as StatusFilter) || "all");
  const [text, setText] = useState(query.get("q") ?? "");
  const [sort, setSort] = useState<Sort>("newest");
  const [shown, setShown] = useState(PAGE);

  // Keep the filters in the URL so a filtered queue can be bookmarked or shared.
  useEffect(() => {
    const q = new URLSearchParams();
    if (verdict !== "all") q.set("verdict", verdict);
    if (status !== "all") q.set("status", status);
    if (text) q.set("q", text);
    const qs = q.toString();
    history.replaceState(null, "", `#/queue${qs ? `?${qs}` : ""}`);
    setShown(PAGE);
  }, [verdict, status, text]);

  const all = cases.data ?? [];
  const rows = useMemo(() => {
    const needle = text.trim().toLowerCase();
    const matches = all.filter((c) => {
      if (verdict !== "all" && c.verdict !== verdict) return false;
      if (status === "active" ? !(c.status === "open" || c.status === "in_review") : status !== "all" && c.status !== status) return false;
      if (!needle) return true;
      return `${c.subject} ${c.sender} ${c.ref} ${c.top_finding ?? ""}`.toLowerCase().includes(needle);
    });
    const by: Record<Sort, (a: CaseSummary, b: CaseSummary) => number> = {
      newest: (a, b) => Date.parse(b.created_at) - Date.parse(a.created_at),
      score: (a, b) => b.score - a.score,
      reports: (a, b) => b.report_count - a.report_count || b.score - a.score,
    };
    return matches.sort(by[sort]);
  }, [all, verdict, status, text, sort]);

  const count = (v: Verdict) => all.filter((c) => c.verdict === v).length;

  if (cases.error) return <ErrorState error={cases.error} retry={cases.reload} />;
  if (!cases.data) return <PageSkeleton />;

  return (
    <div className="page">
      <PageHeader title="Case queue" sub="Every reported message, de-duplicated into a case. Click one to see exactly why it got its verdict." />

      <Panel pad={false}>
        <div className="toolbar">
          <label className="search">
            <Icon name="search" size={16} />
            <input className="input" placeholder="Search subject, sender or case number" value={text} onChange={(e) => setText(e.target.value)} aria-label="Search cases" />
          </label>
          <Segmented<VerdictFilter> label="Verdict" value={verdict} onChange={setVerdict} options={[
            { value: "all", label: "All" },
            { value: "malicious", label: "Malicious", count: count("malicious") },
            { value: "suspicious", label: "Suspicious", count: count("suspicious") },
            { value: "likely_safe", label: "Safe", count: count("likely_safe") },
          ]} />
          <Segmented<StatusFilter> label="Status" value={status} onChange={setStatus} options={[
            { value: "all", label: "Any status" },
            { value: "active", label: "Needs work" },
            { value: "resolved", label: "Resolved" },
            { value: "auto_closed", label: "Auto-closed" },
          ]} />
          <select className="input select" value={sort} onChange={(e) => setSort(e.target.value as Sort)} aria-label="Sort cases">
            <option value="newest">Newest first</option>
            <option value="score">Highest score</option>
            <option value="reports">Most reported</option>
          </select>
        </div>

        {rows.length === 0 ? (
          <EmptyState title="No cases match" action={<button className="btn btn-ghost" onClick={() => { setVerdict("all"); setStatus("all"); setText(""); }}>Clear filters</button>}>
            Try a different filter or search term.
          </EmptyState>
        ) : (
          <div className="table-wrap">
            <table className="tbl">
              <thead>
                <tr><th>Case</th><th>Message</th><th>Verdict</th><th>Why</th><th className="num">Reports</th><th>Status</th></tr>
              </thead>
              <tbody>
                {rows.slice(0, shown).map((c) => (
                  <tr key={c.id} tabIndex={0} onClick={() => go(`/cases/${c.id}`)} onKeyDown={(e) => e.key === "Enter" && go(`/cases/${c.id}`)}>
                    <td data-label="Case"><span className="mono ref">{c.ref}</span><small className="muted">{timeAgo(c.created_at)}</small></td>
                    <td data-label="Message" className="cell-message">
                      <strong className="ellipsis">{c.subject || "(no subject)"}</strong>
                      <small className="muted ellipsis">{c.sender || "unknown sender"}</small>
                    </td>
                    <td data-label="Verdict" className="cell-verdict">
                      <VerdictBadge verdict={c.verdict} size="sm" />
                      <Meter value={c.score} tone={c.verdict} />
                      <small className="mono muted">{c.score.toFixed(2)}</small>
                    </td>
                    <td data-label="Why" className="cell-why">
                      <span className="ellipsis">{c.top_finding ?? "Nothing unusual found"}</span>
                      <span className="why-tags">
                        {c.finding_count > 1 && <Chip>+{c.finding_count - 1} more</Chip>}
                        {c.has_attachments && <Chip title="Has attachments"><Icon name="clip" size={11} /></Chip>}
                        {c.link_count > 0 && <Chip title={`${c.link_count} link(s)`}><Icon name="link" size={11} /> {c.link_count}</Chip>}
                      </span>
                    </td>
                    <td data-label="Reports" className="num">{c.report_count > 1 ? <Chip tone="accent">{c.report_count}×</Chip> : <span className="muted">1</span>}</td>
                    <td data-label="Status"><StatusPill status={c.status} />{c.resolution && <small className="muted">{c.resolution === "confirmed_phish" ? "phish confirmed" : "false positive"}</small>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <footer className="table-foot">
          <span className="muted">Showing {Math.min(shown, rows.length)} of {rows.length}{rows.length !== all.length ? ` (${all.length} total)` : ""}</span>
          {shown < rows.length && <button className="btn btn-ghost" onClick={() => setShown((s) => s + PAGE)}>Show more</button>}
        </footer>
      </Panel>
    </div>
  );
}
