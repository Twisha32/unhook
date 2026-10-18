"""Builds the static JSON the dashboard demo runs on.

Mail goes through the real pipeline, into a throwaway database, and the demo files are
whatever the API would have returned. Only the timestamps are staged: reports are
spread over the last two weeks so the charts have something to draw. The gap between
"received" and "verdict" is the real measured processing time.
"""

import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select

from .analysis.pipeline import offline_services
from .api import _iso, build_overview, case_detail, case_summary, rule_catalogue
from .db import Case, Indicator, Report, configure, session_scope
from .eval import corpus
from .eval.metrics import CostModel
from .eval.run import evaluate_corpus
from .response import blocklist
from .response.notify import LogNotifier
from .service import process_report, submit_report, update_case, write_case_note
from .settings import Settings

ANALYSTS = ["Dana K.", "Sam R."]
STAFF = ["a.rivera", "b.okafor", "c.nguyen", "d.patel", "e.larsen", "f.mbeki", "g.hoffman", "h.castillo",
         "i.abara", "j.whitmore", "k.tanaka", "l.dubois", "m.sorensen", "n.bergstrom"]


def _stamp(rng: random.Random, now: datetime, bias_recent: bool = True) -> datetime:
    # Weekdays are busier than weekends; the last couple of days are the busiest.
    while True:
        day = rng.randrange(14)
        when = now - timedelta(days=day)
        weight = (0.25 if when.weekday() >= 5 else 1.0) * (1.0 + (14 - day) / 14 if bias_recent else 1.0)
        if rng.random() < weight / 2.0:
            break
    return when.replace(hour=rng.randint(7, 16), minute=rng.randint(0, 59), second=rng.randint(0, 59), microsecond=0)


def build_demo(out: Path, samples_dir: Path, extra_phish: int = 70, extra_ham: int = 90, seed: int = 21,
               eval_report: Path | None = None) -> None:
    rng = random.Random(seed)
    out = Path(out)
    (out / "cases").mkdir(parents=True, exist_ok=True)
    manifest = json.loads((samples_dir / "manifest.json").read_text())
    org = manifest["org"]
    now = datetime.now(UTC).replace(microsecond=0)

    # The demo model is trained on synthetic mail, and the dashboard says so.
    meta = {"name": "Synthetic smoke corpus (demo)", "kind": "synthetic",
            "sources": [{"name": "generator", "label": "mixed", "count": 1200}]}
    report, model = evaluate_corpus(corpus.synthetic(500, 700, seed=7), CostModel(), corpus_meta=meta, workers=1, log=lambda *_: None)
    if eval_report is not None:
        # The demo cases are still scored by the synthetic-trained model above, but the Evaluation
        # page can show a real run instead, for example the one published from the eval workflow.
        report = json.loads(Path(eval_report).read_text())
    services = offline_services(model, org["domains"])
    services.protected_names = org["protected_names"]
    settings = Settings(org_domains=org["domains"], protected_names=org["protected_names"], case_note_provider="template")

    items = []
    for s in manifest["samples"]:
        items.append((_stamp(rng, now), (samples_dir / s["file"]).read_bytes(), s["label"]))
    extras = corpus.synthetic(extra_phish, extra_ham, seed=99)
    for s in extras:
        items.append((_stamp(rng, now), s.raw, "phish" if s.label else "legit"))
    items.sort(key=lambda it: it[0])

    configure("sqlite:///:memory:")
    notifier = LogNotifier()
    truth: dict[int, str] = {}
    with session_scope() as db:
        first_reports: list[tuple[datetime, bytes, str]] = []
        for ts, raw, label in items:
            reporter = f"{rng.choice(STAFF)}@{org['domains'][0]}"
            r = submit_report(db, raw, reporter)
            db.flush()
            real_received = r.received_at
            process_report(db, r.id, services, notifier, settings)
            if r.status != "done":
                continue
            real_delta = r.verdict_at - real_received if r.verdict_at and real_received else timedelta(0)
            r.received_at, r.verdict_at = ts, ts + real_delta
            case = db.get(Case, r.case_id)
            if case.report_count == 1:
                case.created_at = ts
                truth[case.id] = label
                if label == "phish" and rng.random() < 0.12:
                    first_reports.append((ts, raw, label))
        # A few messages get reported by several people.
        for ts, raw, _ in first_reports[:8]:
            for _ in range(rng.randint(1, 3)):
                later = ts + timedelta(minutes=rng.randint(4, 90))
                r = submit_report(db, raw, f"{rng.choice(STAFF)}@{org['domains'][0]}")
                db.flush()
                real_received = r.received_at
                process_report(db, r.id, services, notifier, settings)
                if r.verdict_at:
                    r.received_at, r.verdict_at = later, later + (r.verdict_at - real_received)
        db.flush()
        for indicator in db.scalars(select(Indicator)):
            indicator.created_at = indicator.case.created_at  # indicators age with the case they came from

        cases = db.scalars(select(Case).order_by(Case.created_at.asc())).all()
        flagged = [c for c in cases if c.verdict != "likely_safe"]
        keep_open = {c.id for c in flagged[-6:]}
        in_review = flagged[-3].id if len(flagged) >= 3 else None
        for c in flagged:
            if c.id in keep_open:
                if c.id == in_review:
                    update_case(db, c, {"status": "in_review", "assignee": ANALYSTS[0]})
                continue
            age_days = (now - c.created_at.replace(tzinfo=UTC)).total_seconds() / 86400
            if rng.random() < (0.93 if age_days > 1 else 0.5):
                phish = truth.get(c.id) == "phish"
                minutes = round(rng.uniform(0.8, 1.6) if c.verdict == "malicious" else rng.uniform(1.8, 4.5), 1)
                update_case(db, c, {"resolution": "confirmed_phish" if phish else "false_positive",
                                    "assignee": rng.choice(ANALYSTS), "analyst_minutes": minutes})
                c.resolved_at = c.created_at + timedelta(minutes=rng.randint(15, 240))
        for c in cases:
            write_case_note(db, c.id, settings)
        db.flush()

        cases = db.scalars(select(Case).order_by(Case.created_at.desc())).all()
        summaries = [case_summary(c) for c in cases]
        for c in cases:
            (out / "cases" / f"{c.id}.json").write_text(json.dumps(case_detail(c)))
        (out / "cases.json").write_text(json.dumps({"total": len(summaries), "items": summaries}))
        (out / "overview.json").write_text(json.dumps(build_overview(db, 14)))
        (out / "rules.json").write_text(json.dumps(rule_catalogue()))
        active = db.scalars(select(Indicator).where(Indicator.state == "active")).all()
        items_out = [{"kind": i.kind, "value": i.value, "reason": i.reason, "case": i.case.ref, "added": _iso(i.created_at)} for i in active]
        (out / "blocklist.json").write_text(json.dumps(items_out))
        (out / "blocklist.txt").write_text(blocklist.render(items_out, "txt")[0])
        all_ind = db.scalars(select(Indicator).order_by(Indicator.created_at.desc()).limit(300)).all()
        (out / "indicators.json").write_text(json.dumps([
            {"id": i.id, "kind": i.kind, "value": i.value, "reason": i.reason, "state": i.state, "case": i.case.ref,
             "created_at": _iso(i.created_at)} for i in all_ind]))
        n_reports = db.scalar(select(Report.id).limit(1)) and len(db.scalars(select(Report)).all())
    (out / "eval.json").write_text(json.dumps(report))
    (out / "meta.json").write_text(json.dumps({
        "generated_at": now.isoformat(),
        "kind": "demo",
        "cases": len(summaries),
        "reports": n_reports,
        "notes": "Synthetic mail pushed through the real pipeline. Timestamps are staged; processing times are measured.",
    }))
    print(f"demo data: {len(summaries)} cases, {n_reports} reports -> {out}")
