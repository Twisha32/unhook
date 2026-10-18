import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import { VerdictBadge } from "./ui";
import { Icon } from "./Icons";
import type { Verdict } from "../lib/types";

type Phase =
  | { name: "idle" }
  | { name: "working" }
  | { name: "done"; verdict: Verdict; message: string; ref: string | null; seconds: number }
  | { name: "failed"; error: string };

// What an employee's "report phishing" button does, in a form: upload a message, get the verdict back.
export function ReportModal({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [reporter, setReporter] = useState("");
  const [phase, setPhase] = useState<Phase>({ name: "idle" });
  const [over, setOver] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const alive = useRef(true);
  useEffect(() => () => { alive.current = false; }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const submit = useCallback(async () => {
    if (!file) return;
    setPhase({ name: "working" });
    try {
      const { id } = await api.submitReport(file, reporter.trim());
      for (let i = 0; i < 100 && alive.current; i++) {
        const r = await api.report(id);
        if (r.status === "done") {
          setPhase({ name: "done", verdict: r.verdict!, message: r.message ?? "", ref: r.case ?? null, seconds: r.seconds_to_verdict ?? 0 });
          onDone();
          return;
        }
        if (r.status === "failed") throw new Error(r.error || "The message couldn't be analysed.");
        await new Promise((res) => setTimeout(res, 600));
      }
      throw new Error("Timed out waiting for a verdict.");
    } catch (e) {
      if (alive.current) setPhase({ name: "failed", error: (e as Error).message });
    }
  }, [file, reporter, onDone]);

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby="report-title">
        <header>
          <h2 id="report-title">Report an email</h2>
          <button className="icon-btn" onClick={onClose} aria-label="Close"><Icon name="close" size={18} /></button>
        </header>

        {phase.name === "done" ? (
          <div className="modal-result">
            <VerdictBadge verdict={phase.verdict} size="lg" />
            <p className="reply">{phase.message || "No reply text was generated."}</p>
            <p className="hint">Verdict in {phase.seconds.toFixed(1)} s{phase.ref ? ` · case ${phase.ref}` : ""}</p>
            <div className="modal-actions">
              {phase.ref && <button className="btn btn-ghost" onClick={() => { onClose(); window.location.hash = "/queue"; }}>Open the queue</button>}
              <button className="btn btn-primary" onClick={() => { setFile(null); setPhase({ name: "idle" }); }}>Report another</button>
            </div>
          </div>
        ) : (
          <>
            <div
              className={`drop ${over ? "over" : ""} ${file ? "has-file" : ""}`}
              onDragOver={(e) => { e.preventDefault(); setOver(true); }}
              onDragLeave={() => setOver(false)}
              onDrop={(e) => { e.preventDefault(); setOver(false); const f = e.dataTransfer.files[0]; if (f) setFile(f); }}
              onClick={() => input.current?.click()}
              role="button" tabIndex={0}
              onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && input.current?.click()}
            >
              <Icon name={file ? "mail" : "upload"} size={26} />
              <strong>{file ? file.name : "Drop a .eml file here"}</strong>
              <span>{file ? `${(file.size / 1024).toFixed(1)} KB` : "or click to choose one. Forwarded-as-attachment reports work too."}</span>
              <input ref={input} type="file" accept=".eml,message/rfc822" hidden onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
            </div>
            <label className="field">
              <span>Reporter (optional)</span>
              <input className="input" type="email" placeholder="name@yourorg.org" value={reporter} onChange={(e) => setReporter(e.target.value)} />
            </label>
            {phase.name === "failed" && <p className="form-error">{phase.error}</p>}
            <div className="modal-actions">
              <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
              <button className="btn btn-primary" disabled={!file || phase.name === "working"} onClick={submit}>
                {phase.name === "working" ? "Analysing…" : "Get a verdict"}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
