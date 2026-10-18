import { useMemo, useState } from "react";
import { Icon } from "../components/Icons";
import { Chip, ErrorState, PageHeader, PageSkeleton, Segmented } from "../components/ui";
import { api } from "../lib/api";
import { GROUP_LABEL } from "../lib/format";
import { useAsync } from "../lib/hooks";

export function Rules() {
  const rules = useAsync(() => api.rules(), []);
  const [group, setGroup] = useState("all");
  const [text, setText] = useState("");

  const all = rules.data ?? [];
  const groups = useMemo(() => ["all", ...Array.from(new Set(all.map((r) => r.group)))], [all]);
  const visible = all.filter((r) => {
    if (group !== "all" && r.group !== group) return false;
    const needle = text.trim().toLowerCase();
    return !needle || `${r.id} ${r.title} ${r.lesson}`.toLowerCase().includes(needle);
  });

  if (rules.error) return <ErrorState error={rules.error} retry={rules.reload} />;
  if (!rules.data) return <PageSkeleton />;

  return (
    <div className="page">
      <PageHeader
        title="Rules"
        sub={`${all.length} transparent checks. Each one has a fixed confidence, the ATT&CK technique it maps to, and the one-line lesson an employee sees when it fires.`}
      />
      <div className="toolbar toolbar-plain">
        <label className="search">
          <Icon name="search" size={16} />
          <input className="input" placeholder="Search rules" value={text} onChange={(e) => setText(e.target.value)} aria-label="Search rules" />
        </label>
        <Segmented label="Group" value={group} onChange={setGroup} options={groups.map((g) => ({ value: g, label: g === "all" ? "All" : GROUP_LABEL[g] ?? g, count: g === "all" ? undefined : all.filter((r) => r.group === g).length }))} />
      </div>
      <div className="grid cols-3 rules-grid">
        {visible.map((r) => (
          <article key={r.id} className="panel rule" data-group={r.group}>
            <div className="panel-body">
              <div className="rule-top">
                <Chip>{GROUP_LABEL[r.group] ?? r.group}</Chip>
                <span className="rule-conf" title="How confident this rule is on its own"><b>{Math.round(r.confidence * 100)}</b>%</span>
              </div>
              <h3>{r.title}</h3>
              <code className="rule-id">{r.id}</code>
              <p className="rule-lesson">“{r.lesson}”</p>
              <div className="chips">{r.attack.map((a) => <Chip key={a.id} tone="accent" title={a.name}>{a.id}</Chip>)}</div>
              <div className="meter" data-v={r.confidence >= 0.85 ? "malicious" : r.confidence >= 0.55 ? "suspicious" : "likely_safe"}><div className="meter-fill" style={{ width: `${r.confidence * 100}%` }} /></div>
            </div>
          </article>
        ))}
      </div>
      {visible.length === 0 && <p className="muted center">No rules match.</p>}
    </div>
  );
}
