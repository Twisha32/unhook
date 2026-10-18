import { useCallback, useEffect, useState } from "react";
import { Icon, Logo, type IconName } from "./components/Icons";
import { ReportModal } from "./components/ReportModal";
import { PageSkeleton } from "./components/ui";
import { api, detectMode, type Mode } from "./lib/api";
import { useAsync, useHashRoute, useTheme } from "./lib/hooks";
import { Blocklist } from "./pages/Blocklist";
import { CasePage } from "./pages/Case";
import { Evaluation } from "./pages/Evaluation";
import { Overview } from "./pages/Overview";
import { Queue } from "./pages/Queue";
import { Rules } from "./pages/Rules";

const NAV: { path: string; label: string; icon: IconName }[] = [
  { path: "overview", label: "Overview", icon: "overview" },
  { path: "queue", label: "Case queue", icon: "queue" },
  { path: "evaluation", label: "Evaluation", icon: "eval" },
  { path: "rules", label: "Rules", icon: "rules" },
  { path: "blocklist", label: "Blocklist", icon: "block" },
];

export default function App() {
  const [mode, setMode] = useState<Mode | null>(null);
  const [theme, toggleTheme] = useTheme();
  const [reporting, setReporting] = useState(false);
  const [version, setVersion] = useState(0); // bumped after a report so lists refetch
  const route = useHashRoute();

  useEffect(() => { detectMode().then(setMode); }, []);

  const section = route.path[0] ?? "overview";
  const cases = useAsync(() => (mode ? api.cases() : Promise.resolve([])), [mode, version]);
  const openCount = (cases.data ?? []).filter((c) => c.status === "open" || c.status === "in_review").length;
  const refresh = useCallback(() => setVersion((v) => v + 1), []);

  useEffect(() => { window.scrollTo({ top: 0 }); }, [section, route.path[1]]);

  let page = <PageSkeleton />;
  if (mode) {
    if (section === "queue") page = <Queue key={version} query={route.query} />;
    else if (section === "cases") page = <CasePage key={`${route.path[1]}-${version}`} id={route.path[1] ?? ""} onChanged={refresh} />;
    else if (section === "evaluation") page = <Evaluation />;
    else if (section === "rules") page = <Rules />;
    else if (section === "blocklist") page = <Blocklist key={version} />;
    else page = <Overview key={version} />;
  }

  const activeNav = section === "cases" ? "queue" : section;

  return (
    <div className="shell">
      <aside className="sidebar">
        <a className="brand" href="#/overview" aria-label="Unhook home">
          <Logo />
          <span>Unhook</span>
        </a>
        <nav aria-label="Main">
          {NAV.map((n) => (
            <a key={n.path} href={`#/${n.path}`} className="nav-item" aria-current={activeNav === n.path ? "page" : undefined}>
              <Icon name={n.icon} />
              <span>{n.label}</span>
              {n.path === "queue" && openCount > 0 && <em className="nav-count">{openCount}</em>}
            </a>
          ))}
        </nav>
        <div className="sidebar-foot">
          {mode === "live" && (
            <button className="btn btn-primary wide" onClick={() => setReporting(true)}>
              <Icon name="plus" size={16} /> Report an email
            </button>
          )}
          <div className="foot-row">
            <span className="mode-pill" data-mode={mode ?? "demo"} title={mode === "demo" ? "Synthetic mail run through the real pipeline. Nothing here is a real organisation." : "Connected to your Unhook server"}>
              <i />{mode === "live" ? "Live" : "Demo data"}
            </span>
            <button className="icon-btn" onClick={toggleTheme} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`} title="Toggle theme">
              <Icon name={theme === "dark" ? "sun" : "moon"} size={17} />
            </button>
          </div>
        </div>
      </aside>

      <main className="main" key={section}>{page}</main>

      {reporting && <ReportModal onClose={() => setReporting(false)} onDone={refresh} />}
    </div>
  );
}
