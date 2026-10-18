import { useState } from "react";
import { ScoreRing, Waterfall } from "../components/charts";
import { Icon } from "../components/Icons";
import { Chip, CopyButton, Defanged, EmptyState, ErrorState, Meter, PageSkeleton, Panel, StatusPill, VerdictBadge } from "../components/ui";
import { api, currentMode } from "../lib/api";
import { defangHost, fmtBytes, fmtDateTime, FLAG_LABEL, GROUP_LABEL, timeAgo } from "../lib/format";
import { useAsync } from "../lib/hooks";
import type { Analysis, CaseDetail, Finding } from "../lib/types";

const authTone = (v: string) => (v === "pass" ? "ok" : v === "fail" ? "danger" : v === "none" ? "neutral" : "warn");
const tier = (c: number) => (c >= 0.85 ? "malicious" : c >= 0.55 ? "suspicious" : "likely_safe");

export function CasePage({ id, onChanged }: { id: string; onChanged: () => void }) {
  const detail = useAsync(() => api.caseDetail(id), [id]);
  const [hoverEvidence, setHoverEvidence] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState("");

  if (detail.error) return <ErrorState error={detail.error} retry={detail.reload} />;
  if (!detail.data) return <PageSkeleton />;
  const c = detail.data;
  const a = c.analysis;

  const act = async (patch: Parameters<typeof api.updateCase>[1]) => {
    setBusy(true);
    setActionError("");
    try {
      await api.updateCase(c.id, patch);
      detail.reload();
      onChanged();
    } catch (e) {
      setActionError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const findings = [...a.findings].sort((x, y) => y.confidence - x.confidence);

  return (
    <div className="page case">
      <a className="back" href="#/queue"><Icon name="back" size={16} /> Case queue</a>

      <header className="case-head">
        <div className="case-title">
          <div className="case-tags">
            <VerdictBadge verdict={c.verdict} size="lg" />
            <span className="mono ref">{c.ref}</span>
            <StatusPill status={c.status} />
            {c.report_count > 1 && <Chip tone="accent">{c.report_count} people reported this</Chip>}
          </div>
          <h1>{c.subject || "(no subject)"}</h1>
          <p className="muted">
            from <span className="mono">{a.message.from.display ? `${a.message.from.display} ` : ""}&lt;{a.message.from.address.replace(a.message.from.domain, defangHost(a.message.from.domain))}&gt;</span>
            {" · "}reported {timeAgo(c.created_at)}
          </p>
        </div>
      </header>

      <div className="grid case-top">
        <Panel className="verdict-panel">
          <div className="verdict-center">
            <ScoreRing score={a.verdict.score} verdict={c.verdict} thresholds={a.verdict.thresholds} />
            <dl className="verdict-parts">
              <div><dt>Rules</dt><dd>{a.verdict.rules_score.toFixed(2)}</dd></div>
              <div><dt>Model</dt><dd>{a.verdict.model_score === null ? "none" : a.verdict.model_score.toFixed(2)}</dd></div>
            </dl>
            <div className="verdict-scale">
              <Meter value={a.verdict.score} tone={c.verdict} thresholds={a.verdict.thresholds} />
              <div><span>suspicious ≥ {a.verdict.thresholds.suspicious}</span><span>malicious ≥ {a.verdict.thresholds.malicious}</span></div>
            </div>
            {a.verdict.floor !== null && (
              <p className="hint floor"><Icon name="bolt" size={13} /> One high-confidence finding set a minimum score of {a.verdict.floor.toFixed(2)}.</p>
            )}
          </div>
          <Actions c={c} busy={busy} act={act} error={actionError} />
        </Panel>

        <CaseNotePanel c={c} hover={hoverEvidence} setHover={setHoverEvidence} />
      </div>

      <div className="grid case-mid">
        <div className="stack">
          <Panel title={`Findings (${findings.length})`} hint="Every finding names its evidence. The strongest one in each group counts toward the score.">
            {findings.length === 0 ? <p className="muted">No rule fired on this message.</p> : <div className="findings">{findings.map((f) => <FindingCard key={f.rule_id} f={f} />)}</div>}
          </Panel>
        </div>

        <div className="stack">
          <SenderPanel a={a} />
          <AuthPanel a={a} />
          <Panel title="Reports">
            <ul className="timeline">
              {c.reports.map((r) => (
                <li key={r.id}><i /><div><strong>{r.reporter || "anonymous"}</strong><span className="muted">{fmtDateTime(r.received_at)}</span></div></li>
              ))}
            </ul>
          </Panel>
          <Panel title="Indicators" hint="What would go on the blocklist">
            {c.indicators.length === 0 ? <p className="muted">None extracted.</p> : (
              <ul className="indicators">
                {c.indicators.map((i) => (
                  <li key={i.id}>
                    <div><Chip>{i.kind}</Chip><code className="break">{i.value}</code></div>
                    <span className={`state state-${i.state}`}>{i.state === "active" ? "on blocklist" : i.state === "dismissed" ? "dismissed" : "pending review"}</span>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>
      </div>

      <Panel title="How the score was built" hint="Rules say what matched. The model says which features pushed its probability up or down. They are blended at the end.">
        <div className="score-build">
          <div>
            <h4 className="sub">Rules, by group</h4>
            {Object.keys(a.rules.groups).length === 0 ? <p className="muted">No groups scored.</p> : (
              <ul className="groups">
                {Object.entries(a.rules.groups).sort((x, y) => y[1] - x[1]).map(([g, v]) => (
                  <li key={g}><span>{GROUP_LABEL[g] ?? g}</span><Meter value={v} tone={tier(v)} /><b>{v.toFixed(2)}</b></li>
                ))}
              </ul>
            )}
            <p className="hint">Groups combine as independent evidence, so two weak signals from different places can add up.</p>
          </div>
          <div>
            <h4 className="sub">Model, feature by feature {a.model && <small className="muted">v{a.model.version}</small>}</h4>
            {a.model ? <Waterfall baseline={a.model.baseline} contributions={a.model.contributions} /> : <p className="muted">No trained model is loaded, so this verdict comes from the rules alone. Run <code>unhook eval</code> to train one.</p>}
          </div>
        </div>
      </Panel>

      {a.urls.length > 0 && <LinksPanel urls={a.urls} />}
      {a.attachments.length > 0 && <AttachmentsPanel items={a.attachments} />}

      {c.note && c.note.evidence.length > 0 && (
        <Panel title="Evidence" hint="Everything the case note is allowed to cite. Hover a citation above to find its source here.">
          <ol className="evidence">
            {c.note.evidence.map((e) => (
              <li key={e.id} data-active={hoverEvidence === e.id || undefined}>
                <b className="mono">{e.id}</b>
                <Chip>{e.kind}</Chip>
                <code>{e.text}</code>
              </li>
            ))}
          </ol>
        </Panel>
      )}
    </div>
  );
}

function Actions({ c, busy, act, error }: { c: CaseDetail; busy: boolean; act: (p: Parameters<typeof api.updateCase>[1]) => void; error: string }) {
  const demo = currentMode() === "demo";
  const resolved = c.status === "resolved" || c.status === "auto_closed";
  return (
    <div className="actions">
      {resolved ? (
        <>
          <p className="muted">
            {c.status === "auto_closed" ? "Closed automatically: nothing worth an analyst's time." : c.resolution === "confirmed_phish" ? "Confirmed as phishing. Its indicators are on the blocklist." : "Marked as a false positive. Its indicators were dismissed."}
          </p>
          <button className="btn btn-ghost" disabled={busy} onClick={() => act({ status: "open" })}>Reopen</button>
        </>
      ) : (
        <>
          <div className="actions-row">
            <button className="btn btn-danger" disabled={busy} onClick={() => act({ resolution: "confirmed_phish" })}>Confirm phish</button>
            <button className="btn btn-ok" disabled={busy} onClick={() => act({ resolution: "false_positive" })}>False positive</button>
          </div>
          {c.status !== "in_review" && <button className="btn btn-ghost wide" disabled={busy} onClick={() => act({ status: "in_review" })}>Mark in review</button>}
        </>
      )}
      {demo && <p className="hint">Demo mode: actions work in this tab only and reset on reload.</p>}
      {error && <p className="form-error">{error}</p>}
    </div>
  );
}

function CaseNotePanel({ c, hover, setHover }: { c: CaseDetail; hover: string | null; setHover: (id: string | null) => void }) {
  const n = c.note;
  return (
    <Panel
      className="note-panel"
      title="Case note"
      actions={n && <Chip tone={n.source === "llm" ? "accent" : "neutral"} title={n.source === "llm" ? "Written by a language model and verified against the evidence" : "Assembled from the findings without a language model"}>{n.source === "llm" ? "LLM, verified" : "Rule-based"}</Chip>}
    >
      {!n ? <EmptyState title="No note yet">The note is written after the verdict goes out.</EmptyState> : (
        <>
          <p className="note-summary">{n.summary}</p>
          {n.claims.length > 0 && (
            <ul className="claims">
              {n.claims.map((cl, i) => (
                <li key={i}>
                  <span>{cl.text}</span>
                  <span className="cites">
                    {cl.evidence.map((e) => (
                      <button key={e} className="cite" onMouseEnter={() => setHover(e)} onMouseLeave={() => setHover(null)} onFocus={() => setHover(e)} onBlur={() => setHover(null)} data-active={hover === e || undefined}
                        onClick={() => document.querySelector(`.evidence li[data-active]`)?.scrollIntoView({ behavior: "smooth", block: "center" })}>
                        {e}
                      </button>
                    ))}
                  </span>
                </li>
              ))}
            </ul>
          )}
          {n.actions.length > 0 && (
            <div className="next-steps">
              <h4 className="sub">Suggested next steps</h4>
              <ul>{n.actions.map((s, i) => <li key={i}><Icon name="check" size={14} />{s}</li>)}</ul>
            </div>
          )}
          {n.rejected_draft && (
            <p className="banner banner-info">
              <Icon name="info" size={15} />
              <span>A language-model draft was thrown out because {n.rejected_draft.violations.length} claim{n.rejected_draft.violations.length === 1 ? "" : "s"} weren't supported by the evidence. This note was assembled from the findings instead.</span>
            </p>
          )}
        </>
      )}
    </Panel>
  );
}

function FindingCard({ f }: { f: Finding }) {
  return (
    <article className="finding" data-v={tier(f.confidence)}>
      <header>
        <h4>{f.title}</h4>
        <div className="finding-meta">
          <Chip>{GROUP_LABEL[f.group] ?? f.group}</Chip>
          <span className="conf"><b>{Math.round(f.confidence * 100)}</b>% confidence</span>
        </div>
      </header>
      <ul className="finding-evidence">{f.evidence.map((e, i) => <li key={i}><code>{e}</code></li>)}</ul>
      <footer>
        <div className="chips">{f.attack.map((t) => <Chip key={t} tone="accent">{t}</Chip>)}<code className="rule-id">{f.rule_id}</code></div>
        <p className="lesson"><Icon name="sparkle" size={13} /> <span><b>Employee told:</b> {f.lesson}</span></p>
      </footer>
    </article>
  );
}

function SenderPanel({ a }: { a: Analysis }) {
  const m = a.message;
  const mismatch = m.reply_to && m.reply_to.domain !== m.from.domain;
  const rows: [string, React.ReactNode][] = [
    ["Display name", m.from.display || <span className="muted">none</span>],
    ["Address", <Defanged key="addr" value={m.from.address.replace(m.from.domain, defangHost(m.from.domain))} max={34} />],
    ["Reply-To", m.reply_to ? <span className="reply-to" data-warn={mismatch || undefined}>{m.reply_to.address.replace(m.reply_to.domain, defangHost(m.reply_to.domain))}{mismatch && <Chip tone="warn">differs</Chip>}</span> : <span className="muted">same as sender</span>],
    ["Sent", m.date || "—"],
    ["Size", fmtBytes(m.size)],
    ["Relay hops", String(m.received_hops)],
  ];
  return (
    <Panel title="Sender">
      <dl className="kv">{rows.map(([k, v]) => <div key={k}><dt>{k}</dt><dd>{v}</dd></div>)}</dl>
      <div className="hash"><span className="muted">SHA-256</span><code>{m.sha256.slice(0, 16)}…</code><CopyButton text={m.sha256} label="Copy message hash" /></div>
    </Panel>
  );
}

function AuthPanel({ a }: { a: Analysis }) {
  const x = a.auth;
  if (!x.present) {
    return <Panel title="Authentication"><p className="muted">This message carried no authentication results, so SPF, DKIM and DMARC couldn't be checked.</p></Panel>;
  }
  return (
    <Panel title="Authentication" hint={x.authserv ? `Checked by ${x.authserv}` : undefined}>
      <div className="auth-grid">
        {([["SPF", x.spf, x.spf_aligned], ["DKIM", x.dkim, x.dkim_aligned], ["DMARC", x.dmarc, null]] as const).map(([name, v, aligned]) => (
          <div key={name} className={`auth auth-${authTone(v)}`}>
            <span>{name}</span>
            <b>{v}</b>
            {aligned !== null && <small>{aligned ? "aligned" : "not aligned"}</small>}
            {name === "DMARC" && x.dmarc_policy && <small>p={x.dmarc_policy}</small>}
          </div>
        ))}
      </div>
    </Panel>
  );
}

function LinksPanel({ urls }: { urls: Analysis["urls"] }) {
  return (
    <Panel title={`Links (${urls.length})`} hint="Shown defanged. Unhook never fetches these itself." pad={false}>
      <div className="table-wrap">
        <table className="tbl static">
          <thead><tr><th>Destination</th><th>Link text</th><th>Signals</th></tr></thead>
          <tbody>
            {urls.map((u) => (
              <tr key={u.url}>
                <td data-label="Destination" className="cell-url">
                  <Defanged value={u.defanged} max={52} />
                  {u.wrapped && <Chip tone="warn">unwrapped from a security-scanner redirect</Chip>}
                  {u.trace && <TraceChain trace={u.trace} />}
                </td>
                <td data-label="Link text" className="muted">{u.text || "—"}</td>
                <td data-label="Signals">
                  <div className="chips">
                    {u.flags.map((f) => <Chip key={f} tone="warn">{FLAG_LABEL[f] ?? f}</Chip>)}
                    {u.age_days !== null && <Chip tone={u.age_days < 30 ? "danger" : "neutral"}>domain {u.age_days} days old</Chip>}
                    {u.intel.map((i, k) => <Chip key={k} tone="danger" title={i.detail}>{i.source}</Chip>)}
                    {u.flags.length === 0 && u.intel.length === 0 && u.age_days === null && <span className="muted">nothing unusual</span>}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

function TraceChain({ trace }: { trace: NonNullable<Analysis["urls"][number]["trace"]> }) {
  return (
    <div className="trace">
      <span className="trace-title">Sandbox visit</span>
      <ol>
        {trace.hops.map((h, i) => (
          <li key={i}><code>{h.url}</code><em>{h.status ?? "—"}</em></li>
        ))}
      </ol>
      {trace.password_form && <Chip tone="danger"><Icon name="lock" size={11} /> asks for a password</Chip>}
    </div>
  );
}

function AttachmentsPanel({ items }: { items: Analysis["attachments"] }) {
  return (
    <Panel title={`Attachments (${items.length})`} pad={false}>
      <div className="table-wrap">
        <table className="tbl static">
          <thead><tr><th>File</th><th>Type</th><th>Signals</th></tr></thead>
          <tbody>
            {items.map((x) => (
              <tr key={x.sha256}>
                <td data-label="File">
                  <strong className="break">{x.filename}</strong>
                  <small className="muted">{fmtBytes(x.size)} · <span className="mono">{x.sha256.slice(0, 12)}…</span></small>
                </td>
                <td data-label="Type">
                  <span className="mono">{x.sniffed}</span>
                  <small className="muted">claimed {x.declared_type}</small>
                </td>
                <td data-label="Signals">
                  <div className="chips">
                    {x.flags.map((f) => <Chip key={f} tone="warn">{FLAG_LABEL[f] ?? f}</Chip>)}
                    {x.intel.map((i, k) => <Chip key={k} tone="danger" title={i.detail}>{i.source}</Chip>)}
                    {x.flags.length === 0 && x.intel.length === 0 && <span className="muted">nothing unusual</span>}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}
