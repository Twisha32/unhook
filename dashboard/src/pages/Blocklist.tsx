import { useState } from "react";
import { Icon } from "../components/Icons";
import { Chip, CopyButton, EmptyState, ErrorState, PageHeader, PageSkeleton, Panel } from "../components/ui";
import { api, currentMode } from "../lib/api";
import { download, renderBlocklist, type Format } from "../lib/blocklist";
import { timeAgo } from "../lib/format";
import { useAsync } from "../lib/hooks";

const FORMATS: { fmt: Format; label: string; use: string }[] = [
  { fmt: "txt", label: "Domain list", use: "Firewalls and secure web gateways" },
  { fmt: "rpz", label: "DNS RPZ zone", use: "BIND, Unbound, Knot Resolver" },
  { fmt: "csv", label: "CSV", use: "Spreadsheets and SIEM imports" },
  { fmt: "json", label: "JSON", use: "Scripts and custom tooling" },
];

export function Blocklist() {
  const items = useAsync(() => api.blocklist(), []);
  const [kind, setKind] = useState("all");
  if (items.error) return <ErrorState error={items.error} retry={items.reload} />;
  if (!items.data) return <PageSkeleton />;

  const all = items.data;
  const kinds = ["all", ...Array.from(new Set(all.map((i) => i.kind)))];
  const rows = all.filter((i) => kind === "all" || i.kind === kind);
  const demo = currentMode() === "demo";

  return (
    <div className="page">
      <PageHeader title="Blocklist" sub="Indicators from confirmed phishing. Malicious cases land here automatically; suspicious ones wait for an analyst to confirm." />

      <div className="grid cols-4 feeds">
        {FORMATS.map((f) => (
          <div key={f.fmt} className="panel">
            <div className="panel-body feed">
              <strong>{f.label}</strong>
              <span className="muted">{f.use}</span>
              {demo ? (
                <button className="btn btn-ghost" onClick={() => download(`unhook-blocklist.${f.fmt === "rpz" ? "rpz.zone" : f.fmt}`, renderBlocklist(all, f.fmt))}>
                  <Icon name="download" size={15} /> Download
                </button>
              ) : (
                <div className="feed-url">
                  <code>{`/api/blocklist/${f.fmt}`}</code>
                  <CopyButton text={`${window.location.origin}${api.blocklistUrl(f.fmt).split("?")[0]}`} label="Copy feed URL" />
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      <Panel
        title={`${rows.length} active indicators`}
        hint="Shared platforms and well-known brands are never blocked by domain. They only appear here as URL indicators."
        actions={
          <div className="seg" role="group" aria-label="Indicator type">
            {kinds.map((k) => <button key={k} aria-pressed={kind === k} onClick={() => setKind(k)}>{k === "all" ? "All" : k}</button>)}
          </div>
        }
        pad={false}
      >
        {rows.length === 0 ? (
          <EmptyState title="Nothing blocked yet">Indicators show up here when a case is confirmed as phishing.</EmptyState>
        ) : (
          <div className="table-wrap">
            <table className="tbl static">
              <thead><tr><th>Type</th><th>Value</th><th>Reason</th><th>Case</th><th>Added</th></tr></thead>
              <tbody>
                {rows.slice(0, 200).map((i) => (
                  <tr key={`${i.kind}:${i.value}:${i.case}`}>
                    <td data-label="Type"><Chip>{i.kind}</Chip></td>
                    <td data-label="Value"><code className="break">{i.value}</code></td>
                    <td data-label="Reason" className="muted">{i.reason}</td>
                    <td data-label="Case"><a className="mono" href={`#/queue?q=${encodeURIComponent(i.case)}`}>{i.case}</a></td>
                    <td data-label="Added" className="muted">{timeAgo(i.added)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
