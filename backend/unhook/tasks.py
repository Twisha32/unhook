import logging

from celery import Celery

from . import service
from .db import session_scope
from .settings import get_settings

log = logging.getLogger(__name__)
settings = get_settings()

celery_app = Celery("unhook", broker=settings.redis_url)
celery_app.conf.update(
    task_always_eager=settings.eager,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_default_queue="unhook",
    broker_connection_retry_on_startup=True,
)


@celery_app.task(name="unhook.process_report", bind=True, max_retries=2, default_retry_delay=10)
def process_report(self, report_id: str) -> str:
    # Verdict first, case note second: the employee is waiting on the first one.
    with session_scope() as db:
        report = service.process_report(db, report_id)
        case_id = report.case_id
        failed = report.status == "failed"
    if failed:
        raise self.retry(exc=RuntimeError(f"report {report_id} failed"))
    if case_id:
        write_note.delay(case_id)
    return report_id


@celery_app.task(name="unhook.write_note")
def write_note(case_id: int) -> None:
    with session_scope() as db:
        case = db.get(service.Case, case_id)
        if case is not None and case.note is None:
            service.write_case_note(db, case_id)
