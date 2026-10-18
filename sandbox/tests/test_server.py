import pytest
from fastapi.testclient import TestClient

from unhook_sandbox import browser
from unhook_sandbox.server import create_app


@pytest.fixture
def client(lab):
    return TestClient(create_app(lab))


def test_trace_endpoint_returns_what_the_backend_reads(client, site):
    site.add("/", "<title>Hello</title>")
    body = client.post("/trace", json={"url": site.url("/")}).json()
    assert body["title"] == "Hello" and body["hops"][0]["status"] == 200


def test_refusals_are_a_normal_answer_not_a_server_error(client):
    r = client.post("/trace", json={"url": "file:///etc/passwd"})
    assert r.status_code == 200 and r.json()["error"].startswith("refused")


def test_bad_payloads_are_422(client):
    assert client.post("/trace", json={}).status_code == 422
    assert client.post("/trace", json={"url": "http://x.example/" + "a" * 3000}).status_code == 422
    assert client.post("/trace", json={"url": "http://x.example/", "mode": "teleport"}).status_code == 422


def test_healthz_reports_the_setup(client):
    h = client.get("/healthz").json()
    assert h["ok"] and h["default_mode"] == "http" and h["browser"] == browser.available()
