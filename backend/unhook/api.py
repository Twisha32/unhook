import hmac
import json
import statistics
from collections import Counter
from datetime import UTC, datetime, timedelta

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from . import service
from .analysis.attack import TECHNIQUES
from .analysis.rules import RULES
from .db import Case, Indicator, Report, configure, get_db
from .response import blocklist
from .settings import get_settings


def require_token(request: Request):
    token = get_settings().api_token
    if not token:
        return
    supplied = request.headers.get("authorization", "").removeprefix("Bearer ").strip() or request.query_params.get("token", "")
    if not hmac.compare_digest(supplied.encode(), token.encode()):
        raise HTTPException(401, "missing or wrong API token")


def _utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _iso(dt: datetime | None) -> str | None:
    dt = _utc(dt)
    return dt.isoformat() if dt else None


def case_summary(c: Case) -> dict:
    return {
        "id": c.id,
        "ref": c.ref,
        "created_at": _iso(c.created_at),
        "subject": c.subject,
        "sender": c.sender,
        "sender_domain": c.sender_domain,
        "verdict": c.verdict,
        "score": round(c.score, 3),
        "status": c.status,
        "resolution": c.resolution,
        "assignee": c.assignee,
        "report_count": c.report_count,
        "top_finding": c.top_finding,
        "finding_count": len(c.analysis.get("findings", [])),
        "attack": [t["id"] for t in c.analysis.get("attack", []) if "." in t["id"] or t["id"] == "T1566"][:4],
        "has_attachments": bool(c.analysis.get("attachments")),
        "link_count": len(c.analysis.get("urls", [])),
    }


def case_detail(c: Case) -> dict:
    out = case_summary(c)
    out.update({
        "analysis": c.analysis,
        "note": c.note,
        "analyst_minutes": c.analyst_minutes,
        "resolved_at": _iso(c.resolved_at),
        "reports": [
            {"id": r.id, "reporter": r.reporter, "received_at": _iso(r.received_at), "verdict_at": _iso(r.verdict_at)}
            for r in sorted(c.reports, key=lambda r: r.received_at)
        ],
        "indicators": [
            {"id": i.id, "kind": i.kind, "value": i.value, "reason": i.reason, "state": i.state} for i in c.indicators
        ],
    })
    return out


class CaseUpdate(BaseModel):
    status: str | None = None
    resolution: str | None = None
    assignee: str | None = None
    analyst_minutes: float | None = None


def rule_catalogue() -> list[dict]:
    return [
        {"id": r.id, "title": r.title, "group": r.group, "confidence": r.confidence, "lesson": r.lesson,
         "attack": [{"id": t, "name": TECHNIQUES.get(t, t)} for t in r.attack]}
        for r in RULES
    ]


def create_app() -> FastAPI:
    settings = get_settings()
    configure()
    app = FastAPI(title="Unhook", version="0.1.0", docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_methods=["*"], allow_headers=["*"])

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    # --- intake -------------------------------------------------------------

    @app.post("/api/reports", status_code=202, dependencies=[Depends(require_token)])
    async def create_report(request: Request, file: UploadFile | None = File(None), reporter: str = Form(""),
                            db: Session = Depends(get_db)):
        raw = await file.read() if file is not None else await request.body()
        try:
            report = service.submit_report(db, raw, reporter)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        db.commit()
        from .tasks import process_report  # imported here so the API starts without a broker

        process_report.delay(report.id)
        return {"id": report.id, "status": "queued"}

    @app.get("/api/reports/{report_id}", dependencies=[Depends(require_token)])
    def get_report(report_id: str, db: Session = Depends(get_db)):
        r = db.get(Report, report_id)
        if r is None:
            raise HTTPException(404, "no such report")
        out = {"id": r.id, "status": r.status, "received_at": _iso(r.received_at)}
        if r.status == "done":
            out.update({
                "verdict": r.verdict,
                "subject": r.reply_subject,
                "message": r.reply_body,
                "case": r.case.ref if r.case else None,
                "seconds_to_verdict": round((_utc(r.verdict_at) - _utc(r.received_at)).total_seconds(), 1),
            })
        elif r.status == "failed":
            out["error"] = r.error
        return out

    # --- cases --------------------------------------------------------------

    @app.get("/api/cases", dependencies=[Depends(require_token)])
    def list_cases(verdict: str | None = None, status: str | None = None, q: str | None = None,
                   limit: int = Query(100, le=500), offset: int = 0, db: Session = Depends(get_db)):
        stmt = select(Case).order_by(Case.created_at.desc())
        if verdict:
            stmt = stmt.where(Case.verdict == verdict)
        if status:
            stmt = stmt.where(Case.status == status)
        if q:
            like = f"%{q}%"
            stmt = stmt.where(or_(Case.subject.ilike(like), Case.sender.ilike(like), Case.sender_domain.ilike(like)))
        total = db.scalar(select(func.count()).select_from(stmt.subquery()))
        rows = db.scalars(stmt.limit(limit).offset(offset)).all()
        return {"total": total, "items": [case_summary(c) for c in rows]}

    @app.get("/api/cases/{case_id}", dependencies=[Depends(require_token)])
    def get_case(case_id: int, db: Session = Depends(get_db)):
        c = db.get(Case, case_id)
        if c is None:
            raise HTTPException(404, "no such case")
        return case_detail(c)

    @app.patch("/api/cases/{case_id}", dependencies=[Depends(require_token)])
    def patch_case(case_id: int, body: CaseUpdate, db: Session = Depends(get_db)):
        c = db.get(Case, case_id)
        if c is None:
            raise HTTPException(404, "no such case")
        try:
            service.update_case(db, c, body.model_dump(exclude_unset=True))
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        db.flush()
        return case_detail(c)

    @app.post("/api/cases/{case_id}/note", dependencies=[Depends(require_token)])
    def regenerate_note(case_id: int, db: Session = Depends(get_db)):
        try:
            c = service.write_case_note(db, case_id)
        except LookupError as exc:
            raise HTTPException(404, "no such case") from exc
        return case_detail(c)

    # --- feeds and reference data ----------------------------------------------

    @app.get("/api/blocklist/{fmt}", dependencies=[Depends(require_token)])
    def get_blocklist(fmt: str, db: Session = Depends(get_db)):
        rows = db.scalars(select(Indicator).where(Indicator.state == "active").order_by(Indicator.created_at.desc())).all()
        items = [{"kind": i.kind, "value": i.value, "reason": i.reason, "case": i.case.ref, "added": _iso(i.created_at)} for i in rows]
        try:
            body, media = blocklist.render(items, fmt)
        except ValueError as exc:
            raise HTTPException(404, str(exc)) from exc
        return PlainTextResponse(body, media_type=media)

    @app.get("/api/indicators", dependencies=[Depends(require_token)])
    def list_indicators(state: str | None = None, db: Session = Depends(get_db)):
        stmt = select(Indicator).order_by(Indicator.created_at.desc()).limit(500)
        if state:
            stmt = stmt.where(Indicator.state == state)
        return [{"id": i.id, "kind": i.kind, "value": i.value, "reason": i.reason, "state": i.state,
                 "case": i.case.ref, "created_at": _iso(i.created_at)} for i in db.scalars(stmt)]

    @app.get("/api/rules", dependencies=[Depends(require_token)])
    def list_rules():
        return rule_catalogue()

    @app.get("/api/eval/latest", dependencies=[Depends(require_token)])
    def latest_eval():
        path = get_settings().eval_report_path
        if not path.exists():
            raise HTTPException(404, "no evaluation report yet; run `unhook eval`")
        return json.loads(path.read_text())

    @app.get("/api/stats/overview", dependencies=[Depends(require_token)])
    def overview(days: int = Query(14, ge=1, le=90), db: Session = Depends(get_db)):
        return build_overview(db, days)

    return app


def build_overview(db: Session, days: int = 14) -> dict:
    s = get_settings()
    cases = db.scalars(select(Case).order_by(Case.created_at.desc()).limit(5000)).all()
    reports = db.scalars(select(Report)).all()
    verdicts = Counter(c.verdict for c in cases)
    status = Counter(c.status for c in cases)

    waits = sorted(
        (_utc(r.verdict_at) - _utc(r.received_at)).total_seconds() for r in reports if r.status == "done" and r.verdict_at
    )
    time_to_verdict = None
    if waits:
        time_to_verdict = {"median_s": round(statistics.median(waits), 3), "p95_s": round(waits[min(int(len(waits) * 0.95), len(waits) - 1)], 3)}

    baseline = len(reports) * s.manual_review_minutes
    actual = sum(c.analyst_minutes for c in cases)

    today = datetime.now(UTC).date()
    buckets = {today - timedelta(days=i): Counter() for i in range(days - 1, -1, -1)}
    for c in cases:
        day = _utc(c.created_at).date()
        if day in buckets:
            buckets[day][c.verdict] += 1
    daily = [{"date": d.isoformat(), **{k: buckets[d][k] for k in ("malicious", "suspicious", "likely_safe")}} for d in buckets]

    rule_counts: Counter = Counter()
    rule_titles: dict[str, str] = {}
    technique_counts: Counter = Counter()
    for c in cases[:1500]:
        for f in c.analysis.get("findings", []):
            rule_counts[f["rule_id"]] += 1
            rule_titles[f["rule_id"]] = f["title"]
        for t in c.analysis.get("attack", []):
            technique_counts[t["id"]] += 1

    auto = status.get("auto_closed", 0)
    return {
        "totals": {
            "reports": len(reports),
            "cases": len(cases),
            "malicious": verdicts.get("malicious", 0),
            "suspicious": verdicts.get("suspicious", 0),
            "likely_safe": verdicts.get("likely_safe", 0),
            "open": status.get("open", 0) + status.get("in_review", 0),
            "resolved": status.get("resolved", 0),
            "auto_closed": auto,
        },
        "auto_resolved_pct": round(100 * auto / len(cases), 1) if cases else 0.0,
        "time_to_verdict": time_to_verdict,
        "analyst_minutes": {"manual_baseline": round(baseline, 1), "actual": round(actual, 1), "saved": round(max(baseline - actual, 0), 1)},
        "daily": daily,
        "top_rules": [{"rule_id": rid, "title": rule_titles[rid], "count": n} for rid, n in rule_counts.most_common(8)],
        "attack": [{"id": tid, "name": TECHNIQUES.get(tid, tid), "count": n} for tid, n in technique_counts.most_common(10)],
    }
