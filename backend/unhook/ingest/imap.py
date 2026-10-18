"""Poll the report mailbox.

Staff forward suspicious mail to a shared address (or an Outlook/Gmail "report
phishing" add-in does it for them). This loop picks up unseen messages, submits each
as a report, queues the analysis and marks the message as seen.

Written against the IMAP spec and exercised with a stub client in the tests, but not
yet against a live Exchange or Gmail mailbox. Expect to tune the folder names.
"""

import imaplib
import logging
import time

from ..db import session_scope
from ..service import submit_report
from ..settings import get_settings

log = logging.getLogger(__name__)


def poll_once(client, folder: str) -> int:
    client.select(folder)
    status, data = client.search(None, "UNSEEN")
    if status != "OK" or not data or not data[0]:
        return 0
    from ..tasks import process_report

    handled = 0
    for num in data[0].split():
        status, parts = client.fetch(num, "(BODY.PEEK[])")
        if status != "OK" or not parts or not isinstance(parts[0], tuple):
            continue
        raw = parts[0][1]
        with session_scope() as db:
            try:
                report = submit_report(db, raw)
            except ValueError as exc:
                log.warning("skipping message %s: %s", num, exc)
                client.store(num, "+FLAGS", "\\Seen")
                continue
            report_id = report.id
        process_report.delay(report_id)
        client.store(num, "+FLAGS", "\\Seen")
        handled += 1
    return handled


def run() -> None:
    s = get_settings()
    if not s.imap_host:
        raise SystemExit("UNHOOK_IMAP_HOST is not set")
    while True:
        try:
            with imaplib.IMAP4_SSL(s.imap_host) as client:
                client.login(s.imap_user, s.imap_password)
                while True:
                    n = poll_once(client, s.imap_folder)
                    if n:
                        log.info("queued %d report(s)", n)
                    time.sleep(s.imap_poll_seconds)
        except (imaplib.IMAP4.error, OSError) as exc:
            log.warning("mailbox connection dropped (%s); retrying in 30s", exc)
            time.sleep(30)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run()
