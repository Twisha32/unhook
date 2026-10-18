"""Optional browser mode.

Some kits only reveal themselves once JavaScript runs: a decoy page that
redirects after a delay, a login form injected by script. This mode loads the
link in a fresh headless Chromium and records what the main frame did.

It is only meant to run inside the locked-down sandbox container, behind the
egress proxy. Chromium is started with --no-sandbox because it can't create
its own user-namespace sandbox in an unprivileged container; the container
(read-only, no capabilities, no route out) is the sandbox instead. That is a
real trade-off and docs/safety.md says so.
"""

import base64
from urllib.parse import urlsplit

from . import guard
from .config import Config
from .tracer import USER_AGENT, Result

SETTLE_MS = 1500  # how long to wait for script-driven redirects after load
LOCAL_SCHEMES = ("about:", "data:", "blob:")


def available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError:
        return False
    return True


def trace(url: str, cfg: Config | None = None) -> dict:
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    cfg = cfg or Config()
    out = Result(mode="browser")
    refused: list[str] = []

    def gate(route):
        """Every request the page makes passes through here, including subresources."""
        target = route.request.url
        if target.startswith(LOCAL_SCHEMES):
            return route.continue_()
        try:
            parsed = guard.parse_target(target, cfg.ports)
            if cfg.proxy:
                guard.check_literal(parsed.host, cfg.allow_private)  # the proxy owns DNS
            else:
                guard.resolve(parsed.host, parsed.port, cfg.allow_private)
        except guard.EgressError as exc:
            refused.append(str(exc))
            return route.abort("blockedbyclient")
        route.continue_()

    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            args=["--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage", "--disable-extensions",
                  "--disable-background-networking", "--no-first-run", "--mute-audio"],
            proxy={"server": cfg.proxy} if cfg.proxy else None,
        )
        try:
            context = browser.new_context(user_agent=USER_AGENT, viewport={"width": 1280, "height": 800},
                                          accept_downloads=False, service_workers="block", ignore_https_errors=True)
            page = context.new_page()
            page.set_default_timeout(cfg.hop_timeout * 1000)
            page.route("**/*", gate)
            page.on("download", lambda d: out.hop(d.url, None, "download refused"))

            def on_response(resp):
                req = resp.request
                if req.is_navigation_request() and req.frame == page.main_frame:
                    note = "redirect" if 300 <= resp.status < 400 else ""
                    out.hop(resp.url, resp.status, note)

            page.on("response", on_response)

            try:
                page.goto(url, wait_until="load")
                page.wait_for_timeout(SETTLE_MS)
            except PlaywrightError as exc:
                out.error = "navigation failed: " + str(exc).splitlines()[0][:160]
                if refused:
                    out.error = f"refused: {refused[0]}"

            out.finish(page.url if page.url != "about:blank" else url)
            if not out.error or out.hops:
                try:
                    out.title = " ".join(page.title().split())[:200]
                    out.text_excerpt = " ".join(page.inner_text("body").split())[:600]
                    out.password_form = page.query_selector("input[type=password]") is not None
                    actions = page.evaluate("[...document.forms].map(f => f.action)")
                    hosts = []
                    for action in actions:
                        host = urlsplit(action).hostname
                        if host and host not in hosts:
                            hosts.append(host)
                    out.form_hosts = hosts
                    shot = page.screenshot(type="jpeg", quality=55)
                    out.screenshot_b64 = base64.b64encode(shot).decode()
                except PlaywrightError:
                    pass  # a half-loaded page still gave us the hops
        finally:
            browser.close()
    return out.as_dict()
