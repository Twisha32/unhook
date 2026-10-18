import { BarList, DailyChart, Donut, Spark } from "../components/charts";
import { Icon } from "../components/Icons";
import { Chip, ErrorState, Meter, PageHeader, PageSkeleton, Panel, StatusPill, VerdictBadge } from "../components/ui";
import { api, currentMode } from "../lib/api";
import { fmtInt, fmtMinutes, fmtSeconds, timeAgo } from "../lib/format";
import { useAsync, useCountUp } from "../lib/hooks";
import type { Overview as OverviewData } from "../lib/types";

function Kpi({ label, value, display, sub, spark, meter, tone }: {
  label: string; value: number; display: (n: number) => string; sub: string; spark?: number[]; meter?: number; tone?: string;
}) {
  const shown = useCountUp(value);
  return (
    <div className="panel kpi">
      <div className="panel-body">
        <span className="kpi-label">{label}</span>
        <strong className="kpi-value" style={tone ? { color: tone } : undefined}>{display(shown)}</strong>
        <span className="kpi-sub">{sub}</span>
        {spark && <Spark values={spark} color={tone ?? "var(--accent)"} />}
        {meter !== undefined && <div className="kpi-meter" data-v="likely_safe"><Meter value={meter} /></div>}
      </div>
    </div>
  );
}

export function Overview() {
  const overview = useAsync(() => api.overview(), []);
  const cases = useAsync(() => api.cases(), []);

  if (overview.error) return <ErrorState error={overview.error} retry={overview.reload} />;
  if (!overview.data) return <PageSkeleton />;
  const o: OverviewData = overview.data;
  const attention = (cases.data ?? [])
    .filter((c) => c.status === "open" || c.status === "in_review")
    .sort((a, b) => b.score - a.score)
    .slice(0, 5);
  const perDay = o.daily.map((d) => d.malicious + d.suspicious + d.likely_safe);
  const days = o.daily.length;

  return (
    <div className="page">
      <PageHeader
        title="Overview"
        sub={`The last ${days} days of reported email${currentMode() === "demo" ? ", from synthetic demo data" : ""}.`}
      />

      <div className="grid cols-4">
        <Kpi label="Reports triaged" value={o.totals.reports} display={fmtInt} sub={`${fmtInt(o.totals.cases)} unique cases after de-duplication`} spark={perDay} />
        <Kpi label="Analyst time saved" value={o.analyst_minutes.saved} display={fmtMinutes} sub={`against ${fmtMinutes(o.analyst_minutes.manual_baseline)} if each report were triaged by hand`} tone="var(--ok)"
          meter={o.analyst_minutes.manual_baseline ? o.analyst_minutes.saved / o.analyst_minutes.manual_baseline : 0} />
        <Kpi label="Closed without an analyst" value={o.auto_resolved_pct} display={(n) => `${n.toFixed(0)}%`} sub={`${fmtInt(o.totals.auto_closed)} cases were clearly fine`} spark={o.daily.map((d) => d.likely_safe)} tone="var(--accent-2)" />
        <Kpi
          label="Median time to verdict"
          value={o.time_to_verdict?.median_s ?? 0}
          display={(n) => (o.time_to_verdict ? fmtSeconds(n) : "—")}
          sub={o.time_to_verdict ? `95th percentile ${fmtSeconds(o.time_to_verdict.p95_s)}${currentMode() === "demo" ? ", offline analysis" : ""}` : "no reports yet"}
        />
      </div>

      <div className="grid cols-3">
        <Panel className="span-2" title="Reports per day" hint="Stacked by the verdict each message received.">
          <DailyChart days={o.daily} />
          <div className="legend">
            <span><i style={{ background: "var(--danger)" }} />Malicious</span>
            <span><i style={{ background: "var(--warn)" }} />Suspicious</span>
            <span><i style={{ background: "var(--ok)" }} />Likely safe</span>
          </div>
        </Panel>
        <Panel title="Verdict mix" hint="Unique cases">
          <div className="donut-wrap">
            <Donut
              segments={[
                { label: "Malicious", value: o.totals.malicious, color: "var(--danger)" },
                { label: "Suspicious", value: o.totals.suspicious, color: "var(--warn)" },
                { label: "Likely safe", value: o.totals.likely_safe, color: "var(--ok)" },
              ]}
            >
              <strong>{fmtInt(o.totals.cases)}</strong>
              <span>cases</span>
            </Donut>
            <ul className="donut-legend">
              {([["malicious", "Malicious"], ["suspicious", "Suspicious"], ["likely_safe", "Likely safe"]] as const).map(([k, label]) => (
                <li key={k} data-v={k}>
                  <i /> <span>{label}</span> <b>{fmtInt(o.totals[k])}</b>
                </li>
              ))}
            </ul>
          </div>
          <div className="mini-stats">
            <div><b>{fmtInt(o.totals.open)}</b><span>waiting for an analyst</span></div>
            <div><b>{fmtInt(o.totals.resolved)}</b><span>resolved</span></div>
          </div>
        </Panel>
      </div>

      <div className="grid cols-3">
        <Panel title="What is firing" hint="Rules that matched most often">
          <BarList rows={o.top_rules.slice(0, 8).map((r) => ({ key: r.rule_id, label: r.title, value: r.count }))} />
        </Panel>
        <Panel title="MITRE ATT&CK" hint="Techniques the findings map to">
          <BarList
            color="var(--accent-2)"
            rows={o.attack.slice(0, 8).map((t) => ({ key: t.id, label: <><Chip tone="accent">{t.id}</Chip> {t.name}</>, value: t.count }))}
          />
        </Panel>
        <Panel title="Needs attention" hint="Highest score first" actions={<a className="link-arrow" href="#/queue?status=open">All open <Icon name="arrow" size={14} /></a>}>
          {attention.length === 0 ? (
            <p className="muted pad-top">Nothing is waiting. Enjoy it while it lasts.</p>
          ) : (
            <ul className="attention">
              {attention.map((c) => (
                <li key={c.id}>
                  <a href={`#/cases/${c.id}`}>
                    <div className="attention-top">
                      <VerdictBadge verdict={c.verdict} size="sm" />
                      <span className="muted">{timeAgo(c.created_at)}</span>
                    </div>
                    <strong>{c.subject || "(no subject)"}</strong>
                    <div className="attention-bottom">
                      <span className="muted ellipsis">{c.top_finding ?? "No findings"}</span>
                      <StatusPill status={c.status} />
                    </div>
                  </a>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  );
}
