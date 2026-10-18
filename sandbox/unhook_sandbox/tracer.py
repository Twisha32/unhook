"""Plain-HTTP redirect tracer.

This is the default mode and it is deliberately boring: GET each hop, read the
status and Location header, parse the page that finally answers. No JavaScript
runs, no cookies are kept, bodies are capped and anything that isn't text is
never read.

Two ways to stay on the right side of the egress policy:

* With a proxy configured (the compose setup) the proxy resolves names, applies
  the IP policy and connects. We only refuse what is wrong on the face of the URL.
* Without one, we resolve the name ourselves, vet every address and then connect
  to the address we vetted, so DNS can't change its answer between the check and
  the connection.
"""

import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

from . import guard, page
from .config import Config

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
REDIRECTS = {301, 302, 303, 307, 308}
TEXTY = ("text/", "application/xhtml")


@dataclass
class Result:
    hops: list[dict] = field(default_factory=list)
    final_url: str = ""
    final_host: str = ""
    title: str = ""
    text_excerpt: str = ""
    password_form: bool = False
    form_hosts: list[str] = field(default_factory=list)
    screenshot_b64: str = ""
    error: str = ""
    mode: str = "http"

    def as_dict(self) -> dict:
        return self.__dict__.copy()

    def hop(self, url: str, status: int | None, note: str = "") -> None:
        self.hops.append({"url": url, "status": status, "note": note})

    def finish(self, url: str) -> "Result":
        self.final_url = url
        self.final_host = urlsplit(url).hostname or ""
        return self


def _origin_form(url: str) -> str:
    parts = urlsplit(url)
    return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")


def _fetch(client: httpx.Client, url: str, cfg: Config) -> tuple[int, dict, str]:
    """One GET. Returns status, headers and (for text responses) a capped body."""
    target = guard.parse_target(url, cfg.ports)
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
               "Accept-Language": "en-US,en;q=0.8"}

    if cfg.proxy:
        guard.check_literal(target.host, cfg.allow_private)
        attempts = [(url, {})]
    else:
        pinned = guard.resolve(target.host, target.port, cfg.allow_private)
        headers["Host"] = target.authority
        attempts = []
        for ip in pinned:
            host = f"[{ip}]" if ":" in ip else ip
            attempts.append((f"{target.scheme}://{host}:{target.port}{_origin_form(url)}", {"sni_hostname": target.host}))

    last: Exception | None = None
    for req_url, ext in attempts:
        try:
            with client.stream("GET", req_url, headers=headers, extensions=ext) as resp:
                if "x-unhook-blocked" in resp.headers:  # the proxy said no, in the only way plain HTTP lets it
                    raise guard.Blocked(resp.headers["x-unhook-blocked"])
                ctype = resp.headers.get("content-type", "").lower()
                body = b""
                if resp.status_code < 300 and ctype.startswith(TEXTY):
                    for chunk in resp.iter_bytes():
                        body += chunk
                        if len(body) >= cfg.max_body:
                            break
                return resp.status_code, dict(resp.headers), body.decode(resp.encoding or "utf-8", errors="replace")
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            last = exc
    raise last or httpx.ConnectError("no address to connect to")


def trace(url: str, cfg: Config | None = None, client: httpx.Client | None = None) -> dict:
    cfg = cfg or Config()
    out = Result()
    owns_client = client is None
    if client is None:
        # verify=False is deliberate. We are looking at hostile pages and a bad
        # certificate is not what protects us here; it is a clue, not a barrier.
        client = httpx.Client(timeout=cfg.hop_timeout, follow_redirects=False, verify=False, trust_env=False,
                              proxy=cfg.proxy or None, headers={"Connection": "close"})
    deadline = time.monotonic() + cfg.deadline
    current = url
    try:
        for _ in range(cfg.max_hops + 1):
            if time.monotonic() > deadline:
                out.error = "gave up: overall time limit reached"
                break
            try:
                status, headers, body = _fetch(client, current, cfg)
            except guard.Blocked as exc:
                out.hop(current, None, f"refused: {exc}")
                out.error = f"refused: {exc}"
                break
            except guard.Unresolvable as exc:
                out.hop(current, None, str(exc))
                out.error = str(exc)
                break
            except httpx.ProxyError as exc:
                out.hop(current, None, "refused by egress proxy")
                out.error = f"refused by egress proxy ({exc})"
                break
            except httpx.HTTPError as exc:
                out.hop(current, None, f"connection failed: {type(exc).__name__}")
                out.error = f"connection failed: {type(exc).__name__}"
                break

            location = headers.get("location")
            if status in REDIRECTS and location:
                out.hop(current, status, "redirect")
                current = urljoin(current, location)
                continue

            facts = page.read(body, current) if body else {}
            unread = status < 300 and not body
            out.hop(current, status, f"not read: {headers.get('content-type', 'unknown type')}" if unread else "")
            if facts.get("refresh"):
                out.hops[-1]["note"] = "meta refresh"
                current = facts["refresh"]
                continue
            for key in ("title", "text_excerpt", "password_form", "form_hosts"):
                if key in facts:
                    setattr(out, key, facts[key])
            break
        else:
            out.error = f"gave up after {cfg.max_hops} redirects"
    finally:
        if owns_client:
            client.close()
    return out.finish(current).as_dict()
