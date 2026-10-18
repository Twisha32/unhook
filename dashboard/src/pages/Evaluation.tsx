import { useMemo, useState } from "react";
import { BarList, CurveChart, ScoreHistogram } from "../components/charts";
import { Icon } from "../components/Icons";
import { Chip, ErrorState, PageHeader, PageSkeleton, Panel } from "../components/ui";
import { api, currentMode } from "../lib/api";
import { economics, flagMetrics, split } from "../lib/economics";
import { fmtInt, fmtMinutes, fmtPct, GROUP_LABEL } from "../lib/format";
import { useAsync } from "../lib/hooks";
import type { CostAssumptions, EvalReport } from "../lib/types";

interface SliderProps { label: string; hint?: string; value: number; min: number; max: number; step: number; onChange: (v: number) => void; format: (v: number) => string }

function Slider({ label, hint, value, min, max, step, onChange, format }: SliderProps) {
  const pct = ((value - min) / (max - min)) * 100;
  return (
    <label className="slider">
      <span className="slider-top"><span>{label}</span><b>{format(value)}</b></span>
      <input type="range" min={min} max={max} step={step} value={value} onChange={(e) => onChange(Number(e.target.value))} style={{ "--pct": `${pct}%` } as React.CSSProperties} />
      {hint && <small>{hint}</small>}
    </label>
  );
}

function Tile({ label, value, sub, tone }: { label: string; value: string; sub?: string; tone?: "ok" | "danger" | "warn" }) {
  return (
    <div className={`tile ${tone ? `tile-${tone}` : ""}`}>
      <span>{label}</span>
      <strong>{value}</strong>
      {sub && <small>{sub}</small>}
    </div>
  );
}

export function Evaluation() {
  const report = useAsync(() => api.evaluation(), []);
  if (report.error) {
    return (
      <div className="page">
        <PageHeader title="Evaluation" />
        <ErrorState error={report.error} retry={report.reload} />
        <p className="muted center">No report yet? Run <code>unhook eval</code> and refresh.</p>
      </div>
    );
  }
  if (!report.data) return <PageSkeleton />;
  return <Loaded r={report.data} />;
}

function Loaded({ r }: { r: EvalReport }) {
  const base = r.operating_point;
  const [suspicious, setSuspicious] = useState(base.suspicious);
  const [malicious, setMalicious] = useState(base.malicious);
  const [costs, setCosts] = useState<CostAssumptions>(r.assumptions);
  const edited = suspicious !== base.suspicious || malicious !== base.malicious || JSON.stringify(costs) !== JSON.stringify(r.assumptions);
  const set = <K extends keyof CostAssumptions>(k: K) => (v: number) => setCosts((c) => ({ ...c, [k]: v }));
  const reset = () => { setSuspicious(base.suspicious); setMalicious(base.malicious); setCosts(r.assumptions); };

  const live = useMemo(() => {
    const p = split(r.scores.phish, suspicious, malicious);
    const h = split(r.scores.ham, suspicious, malicious);
    return { eco: economics(p, h, costs), flag: flagMetrics(p, h, costs.prevalence), p, h };
  }, [r, suspicious, malicious, costs]);

  const nP = r.scores.phish.length, nH = r.scores.ham.length;
  const tp = live.flag.recall * nP, fp = live.flag.fpr * nH;
  const testPrecision = tp + fp === 0 ? 1 : tp / (tp + fp);
  const ci = !edited ? r.metrics.flag.ci95 : undefined;
  const range = (k: string) => (ci?.[k] ? `95% CI ${fmtPct(ci[k][0], 0)}–${fmtPct(ci[k][1], 0)}` : undefined);
  const synthetic = r.corpus.kind === "synthetic";
  const topRules = [...r.per_rule].filter((x) => x.phish_hits + x.ham_hits > 0).sort((a, b) => b.phish_hits + b.ham_hits - (a.phish_hits + a.ham_hits)).slice(0, 12);
  const maxCoef = Math.max(...r.model.top_features.map((f) => Math.abs(f.coef)), 0.01);
  const split3 = r.corpus.splits;

  return (
    <div className="page">
      <PageHeader title="Evaluation" sub="Precision, recall and false-positive rate on a held-out test split, plus what the errors cost in analyst minutes." />

      <div className={`banner ${synthetic ? "banner-warn" : ""}`}>
        <Icon name="info" size={18} />
        <div>
          {synthetic ? (
            <>
              <strong>These numbers come from a synthetic smoke corpus, not real mail.</strong> The generator and the rules were written together, so a high score here only proves the pipeline runs end to end. For honest numbers, run <code>unhook corpora fetch</code> then <code>unhook eval --corpus real</code>.
            </>
          ) : (
            <>
              <strong>Measured on {r.corpus.name}.</strong> Test split only; the model and thresholds never saw it. These archives are old, and an offline run has no domain-age or threat-intel lookups and little sender-authentication data, so read the limitations at the bottom before quoting a number.
              {currentMode() === "demo" && " The cases and overview elsewhere in this demo are synthetic."}
            </>
          )}
        </div>
      </div>

      <Panel
        title="Try your own operating point"
        hint="Everything below is recomputed in your browser from the stored test-set scores."
        actions={edited ? <button className="btn btn-ghost" onClick={reset}>Reset to calibrated</button> : <Chip tone="ok">Calibrated on validation data</Chip>}
      >
        <div className="lab">
          <div className="lab-controls">
            <h4 className="sub">Thresholds</h4>
            <Slider label="Flag for review at" value={suspicious} min={0.02} max={0.98} step={0.01} format={(v) => v.toFixed(2)} onChange={(v) => { setSuspicious(v); if (malicious < v + 0.02) setMalicious(Math.min(0.99, v + 0.02)); }} hint="Scores at or above this go to the queue" />
            <Slider label="Block automatically at" value={malicious} min={0.04} max={0.99} step={0.01} format={(v) => v.toFixed(2)} onChange={(v) => { setMalicious(v); if (suspicious > v - 0.02) setSuspicious(Math.max(0.02, v - 0.02)); }} hint="Scores at or above this are treated as malicious" />
            <h4 className="sub">What things cost</h4>
            <Slider label="Manual triage of one report" value={costs.manual_minutes} min={2} max={30} step={0.5} format={(v) => `${v} min`} onChange={set("manual_minutes")} />
            <Slider label="Reviewing a flagged case" value={costs.triaged_review_minutes} min={0.5} max={15} step={0.5} format={(v) => `${v} min`} onChange={set("triaged_review_minutes")} />
            <Slider label="Confirming a malicious case" value={costs.malicious_review_minutes} min={0.25} max={5} step={0.25} format={(v) => `${v} min`} onChange={set("malicious_review_minutes")} />
            <Slider label="A missed phish" value={costs.miss_minutes} min={30} max={1000} step={10} format={(v) => `${v} min`} onChange={set("miss_minutes")} hint="Cleanup, resets, lost time. Your number will differ." />
            <Slider label="A wrongly blocked email" value={costs.block_error_minutes} min={2} max={120} step={1} format={(v) => `${v} min`} onChange={set("block_error_minutes")} />
            <Slider label="Share of reports that are phishing" value={costs.prevalence} min={0.01} max={0.6} step={0.01} format={(v) => fmtPct(v, 0)} onChange={set("prevalence")} hint="Real mailboxes are mostly ham. Precision depends heavily on this." />
          </div>

          <div className="lab-results">
            <div className="net-hero">
              <span>Net analyst time saved per 1,000 reports</span>
              <strong>{fmtMinutes(live.eco.net)}</strong>
              <small>
                {fmtMinutes(live.eco.baseline)} to triage everything by hand, minus {fmtMinutes(live.eco.review)} of review,{" "}
                {fmtMinutes(live.eco.missed * costs.miss_minutes)} for missed phish and {fmtMinutes(live.eco.falseBlocks * costs.block_error_minutes)} for wrong blocks.
                The calibrated thresholds maximise this on validation data.
              </small>
            </div>
            <div className="tiles">
              <Tile label="Phish caught or flagged" value={fmtPct(live.flag.recall)} sub={range("recall") ?? `${fmtInt(tp)} of ${fmtInt(nP)} in the test split`} tone="ok" />
              <Tile label="Legitimate mail flagged" value={fmtPct(live.flag.fpr)} sub={range("fpr") ?? `${fmtInt(fp)} of ${fmtInt(nH)} in the test split`} tone={live.flag.fpr > 0.1 ? "warn" : undefined} />
              <Tile label={`Precision at ${fmtPct(costs.prevalence, 0)} phishing`} value={fmtPct(live.flag.precision)} sub="of flagged mail, how much is really phishing" />
              <Tile label="Phish missed / 1,000" value={live.eco.missed.toFixed(1)} sub="reports that scored below the flag threshold" tone={live.eco.missed > 5 ? "danger" : undefined} />
              <Tile label="Wrongly blocked / 1,000" value={live.eco.falseBlocks.toFixed(1)} sub="legitimate mail scored as malicious" tone={live.eco.falseBlocks > 5 ? "danger" : undefined} />
              <Tile label="Review time / 1,000" value={fmtMinutes(live.eco.review)} sub="analyst minutes spent on flagged cases" />
            </div>
          </div>
        </div>
      </Panel>

      <div className="grid cols-3">
        <Panel title="ROC curve" hint={`AUC ${r.metrics.auc_roc.toFixed(3)}`}>
          <CurveChart points={r.curves.roc} xLabel="False-positive rate" yLabel="Recall" diagonal marker={{ x: live.flag.fpr, y: live.flag.recall, label: "operating point" }} />
        </Panel>
        <Panel title="Precision–recall" hint={`AUC ${r.metrics.auc_pr.toFixed(3)} at the test split's own mix`}>
          <CurveChart points={r.curves.pr} xLabel="Recall" yLabel="Precision" color="var(--accent-2)" marker={{ x: live.flag.recall, y: testPrecision, label: "operating point" }} />
        </Panel>
        <Panel title="Score distribution" hint="Where each class landed in the test split">
          <ScoreHistogram phish={r.scores.phish} ham={r.scores.ham} suspicious={suspicious} malicious={malicious} />
          <div className="legend"><span><i style={{ background: "var(--danger)" }} />Phishing ({nP})</span><span><i style={{ background: "var(--ok)" }} />Legitimate ({nH})</span></div>
        </Panel>
      </div>

      <div className="grid cols-2">
        <Panel title="Do the rules and the model both earn their place?" hint={`Final score = (1 − α)·rules + α·model, with α = ${r.operating_point.alpha.toFixed(2)} chosen on validation data.`} pad={false}>
          <div className="table-wrap">
            <table className="tbl static compact">
              <thead><tr><th>Variant</th><th className="num">AUC</th><th className="num">Recall</th><th className="num">FPR</th><th className="num">Missed /1k</th><th className="num">Net saved /1k</th></tr></thead>
              <tbody>
                {r.ablation.map((a, i) => (
                  <tr key={a.name} data-strong={i === r.ablation.length - 1 || undefined}>
                    <td data-label="Variant"><strong>{a.name}</strong></td>
                    <td data-label="AUC" className="num mono">{a.auc.toFixed(3)}</td>
                    <td data-label="Recall" className="num mono">{fmtPct(a.recall, 0)}</td>
                    <td data-label="FPR" className="num mono">{fmtPct(a.fpr, 0)}</td>
                    <td data-label="Missed" className="num mono">{a.missed_per_1000.toFixed(1)}</td>
                    <td data-label="Net saved" className="num mono">{fmtMinutes(a.net_saved_per_1000)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
        <Panel title="What the model leans on" hint={`Largest weights of ${r.model.n_features} offline features. Domain age and live lookups are deliberately left out.`}>
          <ul className="coef">
            {r.model.top_features.slice(0, 9).map((f) => (
              <li key={f.feature} data-sign={f.coef >= 0 ? "up" : "down"}>
                <span>{f.label}</span>
                <div className="coef-track"><div style={{ width: `${(Math.abs(f.coef) / maxCoef) * 50}%`, [f.coef >= 0 ? "left" : "right"]: "50%" }} /></div>
                <b className="mono">{f.coef >= 0 ? "+" : "−"}{Math.abs(f.coef).toFixed(2)}</b>
              </li>
            ))}
          </ul>
        </Panel>
      </div>

      <div className="grid cols-2">
        <Panel title="Rules that fired most" hint="Hits on the test split. A rule that only ever fires on phishing has precision 100%." pad={false}>
          <div className="table-wrap">
            <table className="tbl static compact">
              <thead><tr><th>Rule</th><th className="num">Phish</th><th className="num">Ham</th><th className="num">Precision</th></tr></thead>
              <tbody>
                {topRules.map((x) => (
                  <tr key={x.rule_id}>
                    <td data-label="Rule"><strong>{x.title}</strong><small className="muted">{GROUP_LABEL[x.group] ?? x.group} · {Math.round(x.confidence * 100)}% base confidence</small></td>
                    <td data-label="Phish" className="num mono">{x.phish_hits}</td>
                    <td data-label="Ham" className="num mono">{x.ham_hits}</td>
                    <td data-label="Precision" className="num mono">{x.precision === null ? "—" : fmtPct(x.precision, 0)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
        <div className="stack">
          <Panel title="The test setup">
            <dl className="kv wide-kv">
              <div><dt>Corpus</dt><dd>{r.corpus.name}</dd></div>
              <div><dt>Messages read</dt><dd>{fmtInt(r.corpus.messages_read)}{r.corpus.unparseable > 0 && ` (${r.corpus.unparseable} unparseable)`}</dd></div>
              <div><dt>Removed</dt><dd>{fmtInt(r.corpus.duplicates_removed)} duplicates, {fmtInt(r.corpus.label_conflicts_removed)} label conflicts</dd></div>
              <div><dt>Split by</dt><dd>{r.corpus.split_by}, so a sender never lands on both sides</dd></div>
              <div><dt>Train / val / test</dt><dd>{(["train", "val", "test"] as const).map((k) => `${split3[k].phish + split3[k].ham}`).join(" / ")}</dd></div>
              <div><dt>Test split</dt><dd>{split3.test.phish} phishing, {split3.test.ham} legitimate</dd></div>
              <div><dt>Model</dt><dd>logistic regression, C = {r.model.C}, v{r.model.version}</dd></div>
            </dl>
            {r.corpus.licenses && (
              <ul className="licenses">{Object.entries(r.corpus.licenses).map(([k, v]) => <li key={k}><b>{k}</b> {v}</li>)}</ul>
            )}
          </Panel>
          {r.per_source.length > 0 && (
            <Panel title="Flag rate by source">
              <BarList rows={r.per_source.map((s) => ({ key: s.source, label: s.source, value: Math.round(s.flagged * 1000) / 10, sub: `${fmtInt(s.n)} messages, ${fmtPct(s.blocked, 0)} auto-blocked` }))} color="var(--accent)" />
              <p className="hint">Percent of each source flagged. For a phishing source that is recall; for a ham source it is the false-positive rate.</p>
            </Panel>
          )}
        </div>
      </div>

      <Panel title="Limitations, stated plainly">
        <ul className="limits">{r.limitations.map((l, i) => <li key={i}>{l}</li>)}</ul>
        <p className="hint">Cost figures are assumptions you can change above, not measurements. Confidence intervals are cluster-bootstrap over sender domains.</p>
      </Panel>
    </div>
  );
}
