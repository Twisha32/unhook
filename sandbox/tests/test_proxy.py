import asyncio
import socket
import threading

import httpx
import pytest

from unhook_sandbox import tracer
from unhook_sandbox.config import Config
from unhook_sandbox.proxy import Proxy


class RunningProxy:
    """The proxy on its own event loop in a background thread."""

    def __init__(self, cfg):
        self.loop = asyncio.new_event_loop()
        ready = threading.Event()

        async def start():
            self.server = await asyncio.start_server(Proxy(cfg).handle, "127.0.0.1", 0)
            self.port = self.server.sockets[0].getsockname()[1]
            ready.set()

        def run():
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(start())
            self.loop.run_forever()

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        assert ready.wait(5)

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def stop(self):
        self.loop.call_soon_threadsafe(self.server.close)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)


@pytest.fixture
def open_proxy(site, other_site):
    """A proxy that is allowed to reach loopback, so the tests have somewhere to go."""
    p = RunningProxy(Config(allow_private=True, ports=frozenset({site.port, other_site.port})))
    yield p
    p.stop()


@pytest.fixture
def strict_proxy(site):
    p = RunningProxy(Config(ports=frozenset({site.port})))  # production policy
    yield p
    p.stop()


def raw(proxy, payload: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", proxy.port), timeout=5) as s:
        s.sendall(payload)
        chunks = []
        while True:
            try:
                data = s.recv(65536)
            except TimeoutError:
                break
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks)


def test_plain_http_is_forwarded(site, open_proxy):
    site.add("/hello", "hi there")
    with httpx.Client(proxy=open_proxy.url, trust_env=False) as c:
        r = c.get(site.url("/hello"))
    assert r.status_code == 200 and r.text == "hi there"
    assert site.hits == [("/hello", f"127.0.0.1:{site.port}")]


def test_production_policy_refuses_loopback_with_a_reason(site, strict_proxy):
    with httpx.Client(proxy=strict_proxy.url, trust_env=False) as c:
        r = c.get(site.url("/"))
    assert r.status_code == 403 and "public" in r.headers["x-unhook-blocked"]
    assert site.hits == []


def test_connect_tunnels_to_allowed_targets(site, open_proxy):
    site.add("/", "tunnelled")
    reply = raw(open_proxy, f"CONNECT 127.0.0.1:{site.port} HTTP/1.1\r\nHost: x\r\n\r\n".encode()
                + b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
    assert reply.startswith(b"HTTP/1.1 200 Connection established") and b"tunnelled" in reply


def test_connect_to_private_or_odd_ports_is_refused(site, strict_proxy):
    assert raw(strict_proxy, f"CONNECT 127.0.0.1:{site.port} HTTP/1.1\r\n\r\n".encode()).startswith(b"HTTP/1.1 403")
    assert raw(strict_proxy, b"CONNECT example.com:22 HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 403")
    assert raw(strict_proxy, b"CONNECT 169.254.169.254:80 HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 403")


def test_other_methods_and_junk_are_rejected(open_proxy):
    assert raw(open_proxy, b"POST http://x.example/ HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 405")
    assert raw(open_proxy, b"GET /relative HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 400")
    assert raw(open_proxy, b"nonsense\r\n\r\n").startswith(b"HTTP/1.1 400")
    assert raw(open_proxy, b"GET https://x.example/ HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 400")


def test_proxy_headers_do_not_leak_upstream(site, open_proxy):
    site.add("/", "ok")
    reply = raw(open_proxy, f"GET http://127.0.0.1:{site.port}/ HTTP/1.1\r\nHost: wrong\r\nProxy-Authorization: Basic abc\r\n\r\n".encode())
    assert b"200 OK" in reply and site.hits == [("/", f"127.0.0.1:{site.port}")]


def test_tracer_through_the_proxy(site, other_site, open_proxy):
    other_site.add("/end", "<title>Arrived</title>")
    site.redirect("/go", other_site.url("/end"))
    cfg = Config(proxy=open_proxy.url, allow_private=True, ports=frozenset({site.port, other_site.port}), hop_timeout=3)
    r = tracer.trace(site.url("/go"), cfg)
    assert r["title"] == "Arrived" and [h["status"] for h in r["hops"]] == [302, 200]


def test_tracer_reports_a_proxy_refusal_as_a_refusal(site, strict_proxy):
    # "localhost" isn't an IP literal, so only the proxy's DNS-level check can catch it.
    cfg = Config(proxy=strict_proxy.url, ports=frozenset({site.port}), hop_timeout=3)
    r = tracer.trace(f"http://localhost:{site.port}/", cfg)
    assert r["error"].startswith("refused") and site.hits == []
