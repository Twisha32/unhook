"""Client for the link sandbox.

The analyser never fetches a suspicious URL itself. If a sandbox is configured it
asks the sandbox to do it; if not, links are only judged by what we can see
without visiting them.
"""

import logging
from dataclasses import dataclass, field
from typing import Protocol

import httpx

log = logging.getLogger(__name__)


@dataclass
class Hop:
    url: str
    status: int | None = None
    note: str = ""


@dataclass
class Trace:
    start_url: str
    hops: list[Hop] = field(default_factory=list)
    final_url: str = ""
    final_host: str = ""
    title: str = ""
    text_excerpt: str = ""
    password_form: bool = False
    form_hosts: list[str] = field(default_factory=list)
    screenshot_b64: str = ""
    error: str = ""
    mode: str = "http"

    @property
    def distinct_hosts(self) -> list[str]:
        seen: list[str] = []
        for hop in self.hops:
            host = hop.url.split("/")[2].lower() if hop.url.count("/") >= 2 else ""
            if host and host not in seen:
                seen.append(host)
        return seen


class Tracer(Protocol):
    def trace(self, url: str) -> Trace | None: ...


class NullTracer:
    def trace(self, url: str) -> Trace | None:
        return None


class SandboxTracer:
    def __init__(self, base_url: str, timeout: float = 45.0, client: httpx.Client | None = None):
        self.base_url = base_url.rstrip("/")
        self.client = client or httpx.Client(timeout=timeout)

    def trace(self, url: str) -> Trace | None:
        try:
            resp = self.client.post(f"{self.base_url}/trace", json={"url": url})
            resp.raise_for_status()
            body = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("sandbox trace failed for %s: %s", url, exc)
            return None
        return Trace(
            start_url=url,
            hops=[Hop(h["url"], h.get("status"), h.get("note", "")) for h in body.get("hops", [])],
            final_url=body.get("final_url", ""),
            final_host=body.get("final_host", ""),
            title=body.get("title", ""),
            text_excerpt=body.get("text_excerpt", ""),
            password_form=bool(body.get("password_form")),
            form_hosts=body.get("form_hosts", []),
            screenshot_b64=body.get("screenshot_b64", ""),
            error=body.get("error", ""),
            mode=body.get("mode", "http"),
        )
