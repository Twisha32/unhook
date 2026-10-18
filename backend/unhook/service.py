"""The report lifecycle: intake, analysis, case creation, reply to the reporter."""

import logging
import uuid
from functools import lru_cache

from sqlalchemy import select
from sqlalchemy.orm import Session

from .analysis import analyze_message
from .analysis.message import parse, unwrap_report
from .analysis.pipeline import Services, services_from_settings
from .db import Case, Indicator, Report, now
from .response.casenote import generate_note, writer_from_settings
from .response.lessons import employee_message
from .response.notify import Notifier, notifier_from_settings
from .settings import Settings, get_settings

log = logging.getLogger(__name__)

MAX_RAW_BYTES = 30 * 1024 * 1024


@lru_cache
def default_services() -> Services:
    return services_from_settings(get_settings())


@lru_cache
def default_notifier() -> Notifier:
    return notifier_from_settings(get_settings())


def submit_report(db: Session, raw: bytes, reporter: str = "") -> Report:
    if not raw.strip():
        raise ValueError("empty message")
    if len(raw) > MAX_RAW_BYTES:
        raise ValueError("message is too large")
    report = Report(id=uuid.uuid4().hex, raw=raw, reporter=reporter.strip().lower()[:320])
    db.add(report)
    db.flush()
    return report


def _indicator_state(verdict: str) -> str | None:
    # Malicious goes straight to the feed. Suspicious waits for an analyst.
    return {"malicious": "active", "suspicious": "pending"}.get(verdict)


def process_report(db: Session, report_id: str, services: Services | None = None, notifier: Notifier | None = None,
                   settings: Settings | None = None) -> Report:
    settings = settings or get_settings()
    services = services or default_services()
    notifier = notifier or default_notifier()
    report = db.get(Report, report_id)
    if report is None:
        raise LookupError(report_id)

    try:
        original, reporter, _ = unwrap_report(report.raw, settings.org_domains)
        report.reporter = report.reporter or reporter
        msg = parse(original)

        # The same message reported by several people is one case, not several.
        case = db.scalar(select(Case).where(Case.message_sha256 == msg.raw_sha256))
        if case is not None:
            case.report_count += 1
            if case.status == "auto_closed" and case.verdict != "likely_safe":
                case.status = "open"
        else:
            analysis = analyze_message(msg, services, online=True)
            case = _create_case(db, msg, analysis, settings)
        report.case_id = case.id
        subject, body = employee_message(case.analysis, case.ref)
        report.verdict, report.reply_subject, report.reply_body = case.verdict, subject, body
        report.verdict_at = now()
        report.status = "done"
        db.flush()
        if report.reporter:
            try:
                notifier.send(report.reporter, subject, body)
            except Exception:
                log.exception("could not send verdict to %s", report.reporter)
    except Exception as exc:
        log.exception("report %s failed", report_id)
        db.rollback()  # drop any half-built case, then record the failure on the report itself
        report = db.get(Report, report_id)
        report.status = "failed"
        report.error = f"{exc.__class__.__name__}: {exc}"[:500]
        db.flush()
    return report


def _create_case(db: Session, msg, analysis: dict, settings: Settings) -> Case:
    verdict = analysis["verdict"]
    top = analysis["findings"][0]["title"] if analysis["findings"] else ""
    case = Case(
        message_sha256=msg.raw_sha256,
        subject=msg.subject[:500],
        sender=msg.sender.address,
        sender_domain=msg.sender.domain,
        verdict=verdict["label"],
        score=verdict["score"],
        status="auto_closed" if verdict["label"] == "likely_safe" and settings.auto_close_safe else "open",
        top_finding=top,
        analysis=analysis,
    )
    db.add(case)
    db.flush()
    state = _indicator_state(verdict["label"])
    if state:
        for ind in analysis["indicators"]:
            db.add(Indicator(case_id=case.id, kind=ind["kind"], value=ind["value"], reason=ind["reason"], state=state))
    return case


def write_case_note(db: Session, case_id: int, settings: Settings | None = None) -> Case:
    settings = settings or get_settings()
    case = db.get(Case, case_id)
    if case is None:
        raise LookupError(case_id)
    case.note = generate_note(case.analysis, writer_from_settings(settings))
    return case


RESOLUTIONS = {"confirmed_phish", "false_positive", "spam", "benign"}
STATUSES = {"open", "in_review", "resolved", "auto_closed"}
DEFAULT_REVIEW_MINUTES = 2.5


def update_case(db: Session, case: Case, changes: dict) -> Case:
    if "status" in changes:
        if changes["status"] not in STATUSES:
            raise ValueError("unknown status")
        case.status = changes["status"]
    if "assignee" in changes:
        case.assignee = (changes["assignee"] or None)
    if "analyst_minutes" in changes:
        case.analyst_minutes = max(float(changes["analyst_minutes"]), 0.0)
    if "resolution" in changes and changes["resolution"]:
        if changes["resolution"] not in RESOLUTIONS:
            raise ValueError("unknown resolution")
        case.resolution = changes["resolution"]
        case.status = "resolved"
        case.resolved_at = now()
        if not case.analyst_minutes:
            case.analyst_minutes = DEFAULT_REVIEW_MINUTES
        # An analyst's call decides what ends up on the block list.
        state = "active" if case.resolution == "confirmed_phish" else "dismissed"
        for ind in case.indicators:
            ind.state = state
    return case
