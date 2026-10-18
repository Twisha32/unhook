from datetime import UTC, datetime, timedelta

import httpx

from unhook.analysis.domainage import RdapClient
from unhook.analysis.intel import BazaarClient, Intel, LocalFeed, UrlhausClient
from unhook.analysis.message import Link
from unhook.analysis.trace import SandboxTracer
from unhook.analysis.urls import analyze_url


def mock_client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def url_info(href):
    return analyze_url(Link(href))


def test_local_feed_reads_hostfiles_urls_and_bare_hosts(tmp_path):
    (tmp_path / "urlhaus.txt").write_text("# comment\n127.0.0.1 bad.example\nworse.example\nhttp://evil.example/drop.exe\n")
    feed = LocalFeed.from_path(tmp_path)
    assert len(feed) == 3
    assert feed.lookup(url_info("http://bad.example/x"), host_ok=True).source == "urlhaus"
    assert feed.lookup(url_info("http://evil.example/drop.exe"), host_ok=False) is not None
    assert feed.lookup(url_info("http://evil.example/other"), host_ok=False) is None
    assert feed.lookup(url_info("http://fine.example/"), host_ok=True) is None


def test_urlhaus_sends_the_auth_key_and_reads_a_hit():
    seen = {}

    def handler(request):
        seen["key"] = request.headers.get("Auth-Key")
        seen["path"] = request.url.path
        return httpx.Response(200, json={"query_status": "ok", "url_status": "online", "threat": "malware_download",
                                         "tags": ["exe"], "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/"})

    hit = UrlhausClient("k3y", mock_client(handler)).url("http://evil.example/a.exe")
    assert seen == {"key": "k3y", "path": "/v1/url/"}
    assert hit.source == "urlhaus" and "online" in hit.detail and hit.reference.endswith("/url/1/")


def test_urlhaus_no_results_is_not_a_hit():
    client = UrlhausClient("k", mock_client(lambda r: httpx.Response(200, json={"query_status": "no_results"})))
    assert client.url("http://fine.example/") is None


def test_urlhaus_timeouts_and_errors_mean_no_answer_not_clean_and_not_a_crash():
    def boom(request):
        raise httpx.ConnectTimeout("slow")

    assert UrlhausClient("k", mock_client(boom)).url("http://x.example/") is None
    assert UrlhausClient("k", mock_client(lambda r: httpx.Response(500))).host("x.example") is None


def test_urlhaus_answers_are_cached():
    calls = []

    def handler(request):
        calls.append(1)
        return httpx.Response(200, json={"query_status": "no_results"})

    client = UrlhausClient("k", mock_client(handler))
    client.url("http://x.example/")
    client.url("http://x.example/")
    assert len(calls) == 1


def test_host_lookups_are_skipped_for_shared_platforms():
    paths = []

    def handler(request):
        paths.append(request.url.path)
        return httpx.Response(200, json={"query_status": "no_results"})

    intel = Intel(urlhaus=UrlhausClient("k", mock_client(handler)))
    intel.check_url(url_info("https://docs.google.com/forms/d/abc"))
    intel.check_url(url_info("https://small-site.example/x"))
    assert paths.count("/v1/host/") == 1 and paths.count("/v1/url/") == 2


def test_bazaar_hash_hit():
    def handler(request):
        return httpx.Response(200, json={"query_status": "ok", "data": [{"signature": "Emotet", "file_type": "doc"}]})

    hit = BazaarClient("k", mock_client(handler)).sha256("a" * 64)
    assert hit.kind == "hash" and "Emotet" in hit.detail
    miss = BazaarClient("k", mock_client(lambda r: httpx.Response(200, json={"query_status": "hash_not_found"}))).sha256("b" * 64)
    assert miss is None


def test_rdap_age_in_days():
    registered = (datetime.now(UTC) - timedelta(days=12)).strftime("%Y-%m-%dT%H:%M:%SZ")
    client = RdapClient(mock_client(lambda r: httpx.Response(200, json={"events": [{"eventAction": "registration", "eventDate": registered}]})))
    assert client.age_days("newish.com") == 12


def test_rdap_failure_and_reserved_names_return_none_without_a_request():
    calls = []

    def handler(request):
        calls.append(request.url)
        return httpx.Response(404)

    client = RdapClient(mock_client(handler))
    assert client.age_days("missing.com") is None
    assert client.age_days("thing.example") is None and client.age_days("203.0.113.9") is None
    assert len(calls) == 1


def test_sandbox_tracer_maps_the_response():
    def handler(request):
        return httpx.Response(200, json={"hops": [{"url": "http://a.example/", "status": 302}, {"url": "http://b.example/", "status": 200}],
                                         "final_url": "http://b.example/", "final_host": "b.example", "title": "Sign in",
                                         "password_form": True, "mode": "http"})

    t = SandboxTracer("http://sandbox:8080", client=mock_client(handler)).trace("http://a.example/")
    assert t.final_host == "b.example" and t.password_form and t.distinct_hosts == ["a.example", "b.example"]


def test_sandbox_tracer_failure_is_quiet():
    def boom(request):
        raise httpx.ConnectError("down")

    assert SandboxTracer("http://sandbox:8080", client=mock_client(boom)).trace("http://a.example/") is None
