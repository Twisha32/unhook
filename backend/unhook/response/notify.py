import logging
import smtplib
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Protocol

log = logging.getLogger(__name__)


class Notifier(Protocol):
    def send(self, to: str, subject: str, body: str) -> None: ...


@dataclass
class LogNotifier:
    """Writes the reply to the log. The default until SMTP is configured."""

    outbox: list[tuple[str, str, str]] = field(default_factory=list)

    def send(self, to: str, subject: str, body: str) -> None:
        self.outbox.append((to, subject, body))
        log.info("would email %s: %s", to, subject)


@dataclass
class SmtpNotifier:
    host: str
    port: int
    user: str
    password: str
    sender: str

    def send(self, to: str, subject: str, body: str) -> None:
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = self.sender, to, subject
        msg["Auto-Submitted"] = "auto-generated"  # keeps out-of-office bots from replying to us
        msg.set_content(body)
        with smtplib.SMTP(self.host, self.port, timeout=15) as smtp:
            smtp.starttls()
            if self.user:
                smtp.login(self.user, self.password)
            smtp.send_message(msg)


def notifier_from_settings(settings) -> Notifier:
    if settings.smtp_host:
        return SmtpNotifier(settings.smtp_host, settings.smtp_port, settings.smtp_user, settings.smtp_password, settings.smtp_from)
    return LogNotifier()
