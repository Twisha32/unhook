import socket

import pytest

from unhook_sandbox import guard


@pytest.mark.parametrize("addr", ["8.8.8.8", "93.184.216.34", "2606:4700:4700::1111"])
def test_public_addresses_are_allowed(addr):
    assert guard.ip_allowed(addr)


@pytest.mark.parametrize("addr", [
    "127.0.0.1", "10.1.2.3", "172.16.0.9", "192.168.1.1", "169.254.169.254",  # loopback, RFC 1918, cloud metadata
    "100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "fe80::1", "fc00::1",
    "::ffff:127.0.0.1", "::ffff:10.0.0.1",  # v4-mapped
    "2002:7f00:0001::", "64:ff9b::a00:1",  # 6to4 and NAT64 wrapping private v4
    "203.0.113.9",  # documentation range: not routable
    "not-an-ip",
])
def test_everything_else_is_refused(addr):
    assert not guard.ip_allowed(addr)


def test_private_flag_is_for_tests_and_still_refuses_nonsense():
    assert guard.ip_allowed("127.0.0.1", allow_private=True)
    assert not guard.ip_allowed("0.0.0.0", allow_private=True)
    assert not guard.ip_allowed("224.0.0.1", allow_private=True)


def test_parse_target_accepts_ordinary_links():
    t = guard.parse_target("https://Login.Example.com./path?q=1")
    assert (t.scheme, t.host, t.port, t.authority) == ("https", "login.example.com", 443, "login.example.com")
    assert guard.parse_target("http://x.example:8080/").authority == "x.example:8080"


@pytest.mark.parametrize("url", [
    "file:///etc/passwd", "ftp://x.example/", "gopher://x.example/", "javascript:alert(1)", "//x.example/",
    "http://x.example:22/", "http://x.example:6379/", "http://user:pw@x.example/", "http:///nohost", "http://x.example:99999/",
])
def test_parse_target_refuses_what_it_should(url):
    with pytest.raises(guard.Blocked):
        guard.parse_target(url)


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "2130706433", "0x7f.1", "[::1]"])
def test_names_that_point_home_are_refused_whatever_the_spelling(host):
    # getaddrinfo understands the decimal and hex spellings, so judging resolved addresses catches them.
    with pytest.raises(guard.Blocked):
        guard.resolve(host.strip("[]"), 80)


def test_one_bad_answer_refuses_the_whole_name(monkeypatch):
    answers = [(socket.AF_INET, 1, 6, "", ("93.184.216.34", 80)), (socket.AF_INET, 1, 6, "", ("10.0.0.5", 80))]
    monkeypatch.setattr(guard.socket, "getaddrinfo", lambda *a, **k: answers)
    with pytest.raises(guard.Blocked):
        guard.resolve("mixed.test", 80)


def test_unresolvable_is_not_the_same_as_blocked(monkeypatch):
    def fail(*a, **k):
        raise socket.gaierror("nope")

    monkeypatch.setattr(guard.socket, "getaddrinfo", fail)
    with pytest.raises(guard.Unresolvable):
        guard.resolve("nothing.test", 80)


def test_literal_check_only_cares_about_literals():
    guard.check_literal("login.example.com")
    guard.check_literal("8.8.8.8")
    with pytest.raises(guard.Blocked):
        guard.check_literal("192.168.0.1")
