import http.server
import threading

import pytest

from unhook_sandbox.config import Config


class Site:
    """A throwaway web server with a route table, bound to a loopback address.

    Routes map a path to (status, headers, body). `hits` records every request so a
    test can prove that something was *not* contacted."""

    def __init__(self, bind="127.0.0.1"):
        self.routes: dict[str, tuple[int, dict, bytes | str]] = {}
        self.hits: list[tuple[str, str]] = []
        site = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                site.hits.append((self.path, self.headers.get("Host", "")))
                status, headers, body = site.routes.get(self.path.split("?")[0], (404, {}, "not found"))
                data = body.encode() if isinstance(body, str) else body
                self.send_response(status)
                headers = {"Content-Type": "text/html; charset=utf-8", **headers}
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer((bind, 0), Handler)
        self.port = self.server.server_port
        self.bind = bind
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def url(self, path="/"):
        return f"http://{self.bind}:{self.port}{path}"

    def add(self, path, body="", status=200, **headers):
        self.routes[path] = (status, headers, body)
        return self

    def redirect(self, path, to, status=302):
        return self.add(path, "", status, Location=to)

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def site():
    s = Site()
    yield s
    s.close()


@pytest.fixture
def other_site():
    """Second server on a different loopback address, for 'the redirect points somewhere else' tests."""
    s = Site("127.0.0.2")
    yield s
    s.close()


@pytest.fixture
def lab(site, other_site):
    """Config for talking to the test servers: private addresses on, their ports allowed."""
    return Config(allow_private=True, ports=frozenset({site.port, other_site.port}), hop_timeout=3, deadline=10)
