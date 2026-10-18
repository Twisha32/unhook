from conftest import eml

from unhook.analysis.authres import read_auth
from unhook.analysis.message import parse, unwrap_report


def test_prefers_html_links_and_keeps_anchor_text():
    msg = parse(eml(text="plain", html='<p>Hi <a href="https://good.example/a">Open it</a></p>'))
    assert [(k.href, k.text, k.source) for k in msg.links if k.source == "html"] == [("https://good.example/a", "Open it", "html")]


def test_plain_text_urls_are_found_and_cleaned():
    msg = parse(eml(text="See https://a.example/x, or (https://b.example/y). Also www.c.example/z!"))
    hrefs = {k.href for k in msg.links}
    assert {"https://a.example/x", "https://b.example/y", "http://www.c.example/z"} <= hrefs


def test_hidden_text_is_counted_and_not_part_of_visible_text():
    hidden = "x" * 400
    msg = parse(eml(text="t", html=f'<p>Visible words</p><div style="display:none">{hidden}</div>'))
    assert msg.hidden_chars == 400
    assert "xxxx" not in msg.visible_text
    assert "Visible words" in msg.visible_text


def test_nested_hidden_elements_are_not_double_counted():
    msg = parse(eml(text="t", html='<div style="display:none"><span style="display:none">abcdef</span>ghij</div>'))
    assert msg.hidden_chars == 10


def test_forms_and_password_fields_are_detected():
    msg = parse(eml(text="t", html='<form action="https://collector.example/x"><input type="text"><input type="password"></form>'))
    assert msg.forms and msg.forms[0].has_password
    assert any(k.source == "form" for k in msg.links)


def test_attachment_is_extracted_with_hashes():
    msg = parse(eml(attachments=[("a.bin", b"hello", "application", "octet-stream")]))
    att = msg.attachments[0]
    assert (att.filename, att.size) == ("a.bin", 5)
    assert att.sha256 == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_path_separators_are_stripped_from_attachment_names():
    msg = parse(eml(attachments=[("..\\..\\evil.txt", b"x", "text", "plain")]))
    assert "\\" not in msg.attachments[0].filename and "/" not in msg.attachments[0].filename


def test_inline_forward_markers_are_noticed():
    msg = parse(eml(text="FYI\n\n---------- Forwarded message ---------\nFrom: someone"))
    assert msg.inline_forward


def test_bad_charset_does_not_crash():
    raw = (b"From: a@b.example\r\nTo: c@d.example\r\nSubject: x\r\n"
           b"Content-Type: text/plain; charset=made-up-charset\r\n\r\ncaf\xe9 au lait\r\n")
    assert "caf" in parse(raw).text


def test_missing_headers_do_not_crash():
    msg = parse(b"Subject: only a subject\r\n\r\nbody")
    assert msg.sender.address == "" and msg.subject == "only a subject"


def test_unwrap_returns_the_original_with_its_headers():
    original = eml(sender="Evil <e@bad.example>", auth="mx.org.example; spf=fail smtp.mailfrom=bad.example; dmarc=fail (p=reject) header.from=bad.example")
    wrapper = eml(sender="Staff <staff@org.example>", subject="Fwd: check this", text="is this real?",
                  attachments=[("original.eml", original, "message", "rfc822")])
    inner, reporter, unwrapped = unwrap_report(wrapper, ["org.example"])
    assert unwrapped and reporter == "staff@org.example"
    parsed = parse(inner)
    assert parsed.sender.address == "e@bad.example"
    assert read_auth(parsed.headers, parsed.sender.domain).dmarc == "fail"


def test_unwrap_handles_eml_files_attached_as_octet_stream():
    original = eml(sender="Evil <e@bad.example>")
    wrapper = eml(sender="Staff <staff@org.example>", attachments=[("suspicious.eml", original, "application", "octet-stream")])
    inner, _, unwrapped = unwrap_report(wrapper, ["org.example"])
    assert unwrapped and parse(inner).sender.address == "e@bad.example"


def test_unwrap_leaves_ordinary_messages_alone():
    raw = eml()
    inner, _, unwrapped = unwrap_report(raw, ["org.example"])
    assert not unwrapped and inner == raw


def test_unwrap_ignores_rfc822_attachment_from_outsiders_when_org_is_configured():
    # An external sender who attaches a message is the phish, not a report.
    wrapper = eml(sender="X <x@elsewhere.example>", attachments=[("a.eml", eml(), "message", "rfc822"), ("b.pdf", b"%PDF-", "application", "pdf")])
    _, _, unwrapped = unwrap_report(wrapper, ["org.example"])
    assert not unwrapped
