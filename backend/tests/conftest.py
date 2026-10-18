import os

# Settings are read once at import, so set the environment before anything from unhook loads.
os.environ.setdefault("UNHOOK_EAGER", "1")
os.environ.setdefault("UNHOOK_DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("UNHOOK_RDAP_ENABLED", "0")
os.environ.setdefault("UNHOOK_MODEL_PATH", "/nonexistent/model.json")
os.environ.setdefault("UNHOOK_API_TOKEN", "")

import email  # noqa: E402
import json  # noqa: E402
from email import policy  # noqa: E402
from email.message import EmailMessage  # noqa: E402
from pathlib import Path  # noqa: E402

import pytest  # noqa: E402

from unhook.analysis.message import parse  # noqa: E402
from unhook.analysis.pipeline import build_context, offline_services  # noqa: E402
from unhook.analysis.rules import evaluate  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "samples"


def eml(*, sender="Pat Lee <pat@friendly.example>", to="staff@org.example", subject="Hello", text="Hi there.", html=None,
        reply_to=None, auth=None, attachments=(), headers=None, in_reply_to=None) -> bytes:
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = sender, to, subject
    msg["Date"] = "Mon, 12 Oct 2026 09:14:22 -0500"
    msg["Message-ID"] = "<t@test.invalid>"
    if reply_to:
        msg["Reply-To"] = reply_to
    if auth:
        msg["Authentication-Results"] = auth
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
    for k, v in (headers or {}).items():
        msg[k] = v
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    for name, data, maintype, subtype in attachments:
        if (maintype, subtype) == ("message", "rfc822"):
            # Real clients attach these as nested messages (7bit), not base64 blobs.
            msg.add_attachment(email.message_from_bytes(data, policy=policy.default), filename=name)
        else:
            msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    return bytes(msg)


def ctx_for(raw: bytes, org_domains=None, protected=None, **overrides):
    svc = offline_services(org_domains=org_domains or [])
    svc.protected_names = protected or []
    ctx = build_context(parse(raw), svc, online=False)
    for key, value in overrides.items():
        setattr(ctx, key, value)
    return ctx


def fired(ctx) -> set[str]:
    return {f.rule_id for f in evaluate(ctx)}


@pytest.fixture(scope="session")
def manifest():
    return json.loads((SAMPLES / "manifest.json").read_text())


@pytest.fixture
def db():
    from unhook import db as dbmod

    dbmod.configure("sqlite:///:memory:")
    with dbmod.session_scope() as session:
        yield session
