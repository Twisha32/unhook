"""One positive and one negative case for every rule.

The meta-test at the bottom fails if a rule is added without both, so the rule set can't
grow faster than its tests.
"""

import io
import zipfile
from unittest.mock import patch

import pytest
from conftest import ctx_for, eml, fired

from unhook.analysis.attachments import MacroReport
from unhook.analysis.intel import IntelHit
from unhook.analysis.rules import RULES, evaluate
from unhook.analysis.trace import Hop, Trace

PDF = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n"
PDF_ACTIVE = b"%PDF-1.7\n1 0 obj\n<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\nendobj\n"
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 32
EXE = b"MZ" + b"\x90\x00" * 32
OLE = bytes.fromhex("D0CF11E0A1B11AE1") + b"\x00" * 64


def encrypted_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", b"filler")
    data = bytearray(buf.getvalue())
    data[6] |= 0x1
    data[data.find(b"PK\x01\x02") + 8] |= 0x1
    return bytes(data)


def plain_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a.txt", b"filler")
    return buf.getvalue()


def link(url, text="click"):
    return eml(text=f"see {url}", html=f'<a href="{url}">{text}</a>')


def with_macros(report):
    raw = eml(attachments=[("Quarterly.doc", OLE, "application", "msword")])
    with patch("unhook.analysis.attachments.scan_macros", return_value=report):
        return ctx_for(raw)


def trace(hops, final="x.example", password=False, title="", text=""):
    t = Trace("http://start.example/", [Hop(h) for h in hops], f"http://{final}/", final, title, text, password)
    return {t.start_url: t}


ORG = ["org.example"]
AR = "mx.x; spf={spf}; dkim={dkim}; dmarc={dmarc} (p=reject) header.from=friendly.example"

# rule id -> (builder of a context that should fire it, builder of one that shouldn't)
CASES = {
    "AUTH_DMARC_FAIL": (
        lambda: ctx_for(eml(auth=AR.format(spf="pass", dkim="pass", dmarc="fail"))),
        lambda: ctx_for(eml(auth=AR.format(spf="pass", dkim="pass", dmarc="pass"))),
    ),
    "AUTH_SPF_DKIM_FAIL": (
        lambda: ctx_for(eml(auth=AR.format(spf="fail", dkim="pass", dmarc="pass"))),
        lambda: ctx_for(eml(auth=AR.format(spf="pass", dkim="pass", dmarc="pass"))),
    ),
    "ID_REPLY_TO_MISMATCH": (
        lambda: ctx_for(eml(reply_to="x@other.example")),
        lambda: ctx_for(eml(reply_to="pat.billing@friendly.example")),
    ),
    "ID_DISPLAY_EMAIL_SPOOF": (
        lambda: ctx_for(eml(sender='"ceo@acme.example" <x@bad.example>')),
        lambda: ctx_for(eml(sender='"Pat Lee" <pat@friendly.example>')),
    ),
    "ID_DISPLAY_BRAND": (
        lambda: ctx_for(eml(sender='"PayPal Security Team" <a@bad.example>')),
        lambda: ctx_for(eml(sender='"PayPal" <service@paypal.com>')),
    ),
    "ID_PROTECTED_NAME": (
        lambda: ctx_for(eml(sender='"Elaine Whitfield" <ew1@gmail.com>'), ORG, ["Elaine Whitfield"]),
        lambda: ctx_for(eml(sender='"Elaine Whitfield" <elaine@org.example>'), ORG, ["Elaine Whitfield"]),
    ),
    "ID_FREEMAIL_ROLE": (
        lambda: ctx_for(eml(sender='"IT Help Desk" <helpdesk88@gmail.com>')),
        lambda: ctx_for(eml(sender='"IT Help Desk" <help@org.example>'), ORG),
    ),
    "ID_BRAND_NO_INFRA": (
        lambda: ctx_for(eml(subject="Your Microsoft 365 mailbox is full", text="Open https://files.other.example/a")),
        lambda: ctx_for(eml(subject="Your Microsoft 365 mailbox is full", text="Open https://login.microsoftonline.com/a")),
    ),
    "ID_FAKE_REPLY": (
        lambda: ctx_for(eml(subject="RE: invoice 441", text="Please pay https://pay.other.example/x")),
        lambda: ctx_for(eml(subject="RE: invoice 441", text="Please pay https://pay.other.example/x", in_reply_to="<abc@x.invalid>")),
    ),
    "DOM_LOOKALIKE_SENDER": (
        lambda: ctx_for(eml(sender="a@paypa1.example")),
        lambda: ctx_for(eml(sender="a@friendly.example")),
    ),
    "DOM_LOOKALIKE_LINK": (
        lambda: ctx_for(link("https://micr0soft-login.example/x")),
        lambda: ctx_for(link("https://www.microsoft.com/x")),
    ),
    "DOM_MIXED_SCRIPT": (
        lambda: ctx_for(link("https://xn--pple-43d.example/")),
        lambda: ctx_for(link("https://apple.com/")),
    ),
    "DOM_PUNYCODE": (
        lambda: ctx_for(link("https://xn--bcher-kva.example/")),
        lambda: ctx_for(link("https://books.example/")),
    ),
    "DOM_YOUNG": (
        lambda: ctx_for(link("https://thing.example/"), ages={"thing.example": 5}),
        lambda: ctx_for(link("https://thing.example/"), ages={"thing.example": 4000}),
    ),
    "URL_IP_HOST": (
        lambda: ctx_for(link("http://203.0.113.9/login")),
        lambda: ctx_for(link("http://login.example/login")),
    ),
    "URL_TEXT_MISMATCH": (
        lambda: ctx_for(link("https://evil.example/x", "https://www.mybank.com/login")),
        lambda: ctx_for(link("https://mybank.example/x", "mybank.example")),
    ),
    "URL_USERINFO": (
        lambda: ctx_for(link("https://mybank.com@evil.example/x")),
        lambda: ctx_for(link("https://evil.example/x")),
    ),
    "URL_SHORTENER": (
        lambda: ctx_for(link("https://bit.ly/3abc")),
        lambda: ctx_for(link("https://long-form.example/abc")),
    ),
    "URL_RISKY_TLD": (
        lambda: ctx_for(link("https://thing.zip/a")),
        lambda: ctx_for(link("https://thing.org/a")),
    ),
    "URL_FREE_HOSTING": (
        lambda: ctx_for(eml(text="Sign in within 24 hours: https://abc123.pages.dev/x")),
        lambda: ctx_for(eml(text="My portfolio is at https://abc123.pages.dev/x")),
    ),
    "URL_SCRIPT_SCHEME": (
        lambda: ctx_for(eml(text="x", html='<a href="javascript:alert(1)">open</a>')),
        lambda: ctx_for(link("https://fine.example/")),
    ),
    "URL_LONG_CHAIN": (
        lambda: ctx_for(link("http://start.example/"), traces=trace(["http://a.example/", "http://b.example/", "http://c.example/"])),
        lambda: ctx_for(link("http://start.example/"), traces=trace(["http://a.example/"])),
    ),
    "URL_LANDING_LOGIN_FORM": (
        lambda: ctx_for(link("http://start.example/"), traces=trace(["http://a.example/"], "page.example", password=True)),
        lambda: ctx_for(link("http://start.example/"), traces=trace(["http://a.example/"], "page.example", password=False)),
    ),
    "URL_LANDING_BRAND_MISMATCH": (
        lambda: ctx_for(link("http://start.example/"), traces=trace(["http://a.example/"], "page.example", True, "Microsoft sign in")),
        lambda: ctx_for(link("http://start.example/"), traces=trace(["http://a.example/"], "login.microsoftonline.com", True, "Microsoft sign in")),
    ),
    "ATT_DANGEROUS_EXT": (
        lambda: ctx_for(eml(attachments=[("setup.exe", EXE, "application", "octet-stream")])),
        lambda: ctx_for(eml(attachments=[("report.pdf", PDF, "application", "pdf")])),
    ),
    "ATT_DOUBLE_EXT": (
        lambda: ctx_for(eml(attachments=[("Invoice.pdf.exe", EXE, "application", "octet-stream")])),
        lambda: ctx_for(eml(attachments=[("budget.v2.pdf", PDF, "application", "pdf")])),
    ),
    "ATT_DISGUISED_EXE": (
        lambda: ctx_for(eml(attachments=[("photo.jpg", EXE, "image", "jpeg")])),
        lambda: ctx_for(eml(attachments=[("photo.jpg", JPEG, "image", "jpeg")])),
    ),
    "ATT_TYPE_MISMATCH": (
        lambda: ctx_for(eml(attachments=[("report.pdf", JPEG, "application", "pdf")])),
        lambda: ctx_for(eml(attachments=[("report.pdf", PDF, "application", "pdf")])),
    ),
    "ATT_MACRO_AUTOEXEC": (
        lambda: with_macros(MacroReport(True, ["AutoOpen"], ["Shell"], [])),
        lambda: with_macros(MacroReport(True, [], ["Shell"], [])),
    ),
    "ATT_MACRO": (
        lambda: with_macros(MacroReport(True, [], [], [])),
        lambda: with_macros(MacroReport(False)),
    ),
    "ATT_ACTIVE_HTML": (
        lambda: ctx_for(eml(attachments=[("review.html", b"<html><body>hi</body></html>", "text", "html")])),
        lambda: ctx_for(eml(attachments=[("notes.txt", b"just notes", "text", "plain")])),
    ),
    "ATT_PDF_ACTIVE": (
        lambda: ctx_for(eml(attachments=[("doc.pdf", PDF_ACTIVE, "application", "pdf")])),
        lambda: ctx_for(eml(attachments=[("doc.pdf", PDF, "application", "pdf")])),
    ),
    "ATT_ENCRYPTED_ARCHIVE": (
        lambda: ctx_for(eml(attachments=[("files.zip", encrypted_zip(), "application", "zip")])),
        lambda: ctx_for(eml(attachments=[("files.zip", plain_zip(), "application", "zip")])),
    ),
    "TXT_CREDENTIAL_URGENCY": (
        lambda: ctx_for(eml(text="Verify your account within 24 hours: https://acct.other.example/a")),
        lambda: ctx_for(eml(text="Lunch is at noon, menu here: https://menu.other.example/a")),
    ),
    "TXT_PAYMENT_PRESSURE": (
        lambda: ctx_for(eml(sender="Pat <pat@gmail.com>", text="Please send a wire transfer immediately.")),
        lambda: ctx_for(eml(text="Invoice 12 is attached for your records, no rush.")),
    ),
    "TXT_HIDDEN_CONTENT": (
        lambda: ctx_for(eml(text="t", html='<p>hi</p><div style="display:none">' + "w" * 400 + "</div>")),
        lambda: ctx_for(eml(text="t", html='<p>hi</p><div style="display:none">preheader</div>')),
    ),
    "TXT_QR_LURE": (
        lambda: ctx_for(eml(text="Scan the QR code below to continue.")),
        lambda: ctx_for(eml(text="See you at the quarterly review on Tuesday.")),
    ),
    "HTML_PASSWORD_FORM": (
        lambda: ctx_for(eml(text="t", html='<form action="https://c.example/x"><input type="password"></form>')),
        lambda: ctx_for(eml(text="t", html='<form action="https://c.example/x"><input type="text"></form>')),
    ),
    "TXT_GENERIC_GREETING": (
        lambda: ctx_for(eml(text="Dear customer,\nPlease verify your account.")),
        lambda: ctx_for(eml(text="Hi Sam,\nPlease verify your account details with me in person.")),
    ),
    "INTEL_URL_LISTED": (
        lambda: ctx_for(link("http://m.example/a"), intel=[IntelHit("urlhaus", "url", "http://m.example/a", "listed")]),
        lambda: ctx_for(link("http://m.example/a"), intel=[]),
    ),
    "INTEL_HASH_KNOWN": (
        lambda: ctx_for(eml(), intel=[IntelHit("malwarebazaar", "hash", "a" * 64, "known sample")]),
        lambda: ctx_for(eml(), intel=[]),
    ),
}


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_fires_when_it_should(rule_id):
    positive, _ = CASES[rule_id]
    assert rule_id in fired(positive())


@pytest.mark.parametrize("rule_id", sorted(CASES))
def test_rule_stays_quiet_when_it_should(rule_id):
    _, negative = CASES[rule_id]
    assert rule_id not in fired(negative())


def test_every_rule_has_both_cases():
    assert {r.id for r in RULES} == set(CASES), "add a positive and negative case in CASES for every rule"


def test_every_rule_has_a_lesson_and_attack_mapping():
    missing = [r.id for r in RULES if not r.lesson]
    assert not missing, f"rules without a micro-lesson: {missing}"
    unmapped = [r.id for r in RULES if not r.attack]
    assert not unmapped, f"rules without an ATT&CK technique: {unmapped}"


def test_confidences_are_probabilities():
    assert all(0 < r.confidence < 1 for r in RULES)


def test_overlapping_phrases_are_quoted_once_in_the_evidence():
    ctx = ctx_for(eml(text="Verify your account within 24 hours or it will be closed: https://acct.other.example/a"))
    finding = next(f for f in evaluate(ctx) if f.rule_id == "TXT_CREDENTIAL_URGENCY")
    assert " ".join(finding.evidence).count("within 24 hours") == 1


def test_a_small_bakery_is_not_a_lookalike():
    ctx = ctx_for(eml(sender='"Clever Kids Daycare" <hello@cleverkids.example>', text="Pickup is at 4."))
    assert "ID_DISPLAY_BRAND" not in fired(ctx)
