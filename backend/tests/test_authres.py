
from unhook.analysis.authres import read_auth

AR_PASS = "mx.example.net; spf=pass smtp.mailfrom=news.example.com; dkim=pass header.d=example.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com"


def test_reads_all_three_results_and_policy():
    a = read_auth({"authentication-results": [AR_PASS]}, "example.com")
    assert (a.spf, a.dkim, a.dmarc, a.dmarc_policy) == ("pass", "pass", "pass", "reject")
    assert a.present and a.authserv == "mx.example.net"
    assert a.spf_aligned and a.dkim_aligned


def test_failures_are_listed():
    a = read_auth({"authentication-results": ["mx.x; spf=softfail smtp.mailfrom=a.example; dkim=none; dmarc=fail (p=none) header.from=a.example"]}, "a.example")
    assert a.failed == ["spf", "dmarc"]


def test_topmost_header_wins_over_a_forged_one_below():
    forged = "evil.example; spf=pass; dkim=pass; dmarc=pass"
    real = "mx.example.net; spf=fail smtp.mailfrom=x.example; dkim=none; dmarc=fail (p=reject) header.from=x.example"
    a = read_auth({"authentication-results": [real, forged]}, "x.example")
    assert a.dmarc == "fail"


def test_trusted_server_list_skips_headers_from_other_servers():
    headers = {"authentication-results": ["attacker.example; dmarc=pass", "mx.org.example; dmarc=fail header.from=x.example"]}
    a = read_auth(headers, "x.example", trusted_servers=["mx.org.example"])
    assert a.dmarc == "fail"


def test_multiple_dkim_signatures_one_pass_is_enough():
    a = read_auth({"authentication-results": ["mx.x; dkim=fail header.d=a.example; dkim=pass header.d=esp.example"]}, "a.example")
    assert a.dkim == "pass"
    assert a.dkim_aligned is True


def test_dkim_pass_for_an_unrelated_domain_is_not_aligned():
    a = read_auth({"authentication-results": ["mx.x; dkim=pass header.d=esp.example"]}, "brand.example")
    assert a.dkim_aligned is False


def test_received_spf_is_a_fallback():
    a = read_auth({"received-spf": ["fail (domain does not designate sender)"]}, "x.example")
    assert a.spf == "fail" and a.present


def test_no_headers_means_not_present():
    a = read_auth({}, "x.example")
    assert not a.present and a.failed == []
