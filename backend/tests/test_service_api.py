import json

import pytest
from conftest import SAMPLES, eml
from fastapi.testclient import TestClient

from unhook import service
from unhook.api import create_app
from unhook.db import session_scope
from unhook.response.notify import LogNotifier
from unhook.settings import get_settings


@pytest.fixture
def client(monkeypatch):
    notifier = LogNotifier()
    monkeypatch.setattr(service, "default_notifier", lambda: notifier)
    # Same fictional district the samples were written for.
    settings = get_settings()
    monkeypatch.setattr(settings, "org_domains", ["ridgewood-usd.example"])
    monkeypatch.setattr(settings, "protected_names", ["Elaine Whitfield"])
    service.default_services.cache_clear()
    c = TestClient(create_app())
    c.notifier = notifier
    yield c
    service.default_services.cache_clear()


def sample(name):
    return (SAMPLES / name).read_bytes()


def submit(client, raw, reporter="pat@org.example"):
    r = client.post("/api/reports", files={"file": ("m.eml", raw, "message/rfc822")}, data={"reporter": reporter})
    assert r.status_code == 202, r.text
    return r.json()["id"]


def test_a_report_gets_a_verdict_a_case_and_a_reply(client):
    rid = submit(client, sample("01-m365-password-expiry.eml"))
    report = client.get(f"/api/reports/{rid}").json()
    assert report["status"] == "done" and report["verdict"] == "malicious"
    assert "Quick tip" in report["message"] and report["case"].startswith("UH-")
    assert client.notifier.outbox and client.notifier.outbox[0][0] == "pat@org.example"

    cases = client.get("/api/cases").json()
    assert cases["total"] == 1 and cases["items"][0]["verdict"] == "malicious"
    detail = client.get(f"/api/cases/{cases['items'][0]['id']}").json()
    assert detail["analysis"]["findings"] and detail["note"]["source"] == "template"
    assert detail["reports"][0]["reporter"] == "pat@org.example"


def test_the_same_message_reported_twice_is_one_case(client):
    raw = sample("01-m365-password-expiry.eml")
    submit(client, raw, "a@org.example")
    second = submit(client, raw, "b@org.example")
    assert client.get("/api/cases").json()["total"] == 1
    assert client.get("/api/cases/1").json()["report_count"] == 2
    assert client.get(f"/api/reports/{second}").json()["verdict"] == "malicious"


def test_forwarded_reports_are_unwrapped_and_the_reporter_gets_the_answer(client):
    inner = sample("15-irs-spoofed-sender.eml")
    wrapper = eml(sender="Sam <sam@ridgewood-usd.example>", subject="Fwd: is this real?", text="please check",
                  attachments=[("irs.eml", inner, "message", "rfc822")])
    rid = submit(client, wrapper, "")
    report = client.get(f"/api/reports/{rid}").json()
    assert report["verdict"] == "malicious"
    assert client.notifier.outbox[-1][0] == "sam@ridgewood-usd.example"
    assert client.get("/api/cases/1").json()["sender"] == "refunds@irs.gov"


def test_safe_mail_is_auto_closed_and_gets_a_calm_reply(client):
    rid = submit(client, sample("10-staff-meeting.eml"))
    assert client.get(f"/api/reports/{rid}").json()["verdict"] == "likely_safe"
    case = client.get("/api/cases/1").json()
    assert case["status"] == "auto_closed"
    assert "didn't find anything wrong" in client.notifier.outbox[0][2]


def test_malicious_goes_to_the_blocklist_and_false_positive_takes_it_off(client):
    submit(client, sample("01-m365-password-expiry.eml"))
    assert "session-verify.example" in client.get("/api/blocklist/txt").text
    client.patch("/api/cases/1", json={"resolution": "false_positive"})
    assert "session-verify.example" not in client.get("/api/blocklist/txt").text


def test_suspicious_waits_for_an_analyst_before_reaching_the_blocklist(client):
    submit(client, sample("05-hr-payroll-lookalike.eml"))
    assert client.get("/api/cases/1").json()["verdict"] == "suspicious"
    assert "ridgewood-usd-hr.example" not in client.get("/api/blocklist/txt").text
    resolved = client.patch("/api/cases/1", json={"resolution": "confirmed_phish", "assignee": "Dana"}).json()
    assert resolved["status"] == "resolved" and resolved["analyst_minutes"] > 0
    assert "ridgewood-usd-hr.example" in client.get("/api/blocklist/txt").text
    assert "CNAME" in client.get("/api/blocklist/rpz").text


def test_overview_numbers(client):
    submit(client, sample("01-m365-password-expiry.eml"))
    submit(client, sample("10-staff-meeting.eml"))
    client.patch("/api/cases/1", json={"resolution": "confirmed_phish", "analyst_minutes": 2})
    o = client.get("/api/stats/overview").json()
    assert o["totals"]["reports"] == 2 and o["totals"]["malicious"] == 1 and o["totals"]["auto_closed"] == 1
    assert o["analyst_minutes"]["manual_baseline"] == 16.0 and o["analyst_minutes"]["saved"] == 14.0
    assert len(o["daily"]) == 14 and o["time_to_verdict"]["median_s"] >= 0
    assert o["top_rules"] and o["attack"]


def test_filters_and_search(client):
    submit(client, sample("01-m365-password-expiry.eml"))
    submit(client, sample("10-staff-meeting.eml"))
    assert client.get("/api/cases", params={"verdict": "malicious"}).json()["total"] == 1
    assert client.get("/api/cases", params={"q": "PD agenda"}).json()["total"] == 1
    assert client.get("/api/cases", params={"status": "auto_closed"}).json()["total"] == 1


def test_bad_input_is_rejected_politely(client):
    assert client.post("/api/reports", files={"file": ("m.eml", b"   ", "message/rfc822")}).status_code == 400
    assert client.get("/api/reports/nope").status_code == 404
    assert client.get("/api/cases/999").status_code == 404
    submit(client, sample("10-staff-meeting.eml"))
    assert client.patch("/api/cases/1", json={"resolution": "maybe"}).status_code == 400
    assert client.get("/api/blocklist/xml").status_code == 404


def test_raw_rfc822_body_is_accepted_too(client):
    r = client.post("/api/reports", content=sample("10-staff-meeting.eml"), headers={"content-type": "message/rfc822"})
    assert r.status_code == 202


def test_token_protects_the_api(client):
    settings = get_settings()
    settings.api_token = "s3cret"
    try:
        assert client.get("/api/cases").status_code == 401
        assert client.get("/api/cases", headers={"Authorization": "Bearer wrong"}).status_code == 401
        assert client.get("/api/cases", headers={"Authorization": "Bearer s3cret"}).status_code == 200
        assert client.get("/api/blocklist/txt", params={"token": "s3cret"}).status_code == 200
        assert client.get("/healthz").status_code == 200
    finally:
        settings.api_token = ""


def test_rule_catalogue_and_eval_report(client, tmp_path):
    rules = client.get("/api/rules").json()
    assert len(rules) >= 30 and all(r["lesson"] and r["attack"] for r in rules)
    settings = get_settings()
    settings.eval_report_path = tmp_path / "missing.json"
    assert client.get("/api/eval/latest").status_code == 404
    (tmp_path / "r.json").write_text(json.dumps({"schema": 1}))
    settings.eval_report_path = tmp_path / "r.json"
    assert client.get("/api/eval/latest").json() == {"schema": 1}


def test_failed_processing_is_recorded_not_raised(client, monkeypatch):
    monkeypatch.setattr(service, "analyze_message", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    from unhook import tasks

    monkeypatch.setattr(tasks.process_report, "max_retries", 0)
    r = client.post("/api/reports", files={"file": ("m.eml", sample("10-staff-meeting.eml"), "message/rfc822")})
    rid = r.json()["id"]
    state = client.get(f"/api/reports/{rid}").json()
    assert state["status"] == "failed" and "boom" in state["error"]


def test_imap_poller_submits_unseen_mail(client):
    from unhook.ingest.imap import poll_once

    class Stub:
        def __init__(self):
            self.stored = []

        def select(self, folder):
            return "OK", [b"1"]

        def search(self, charset, criteria):
            return "OK", [b"7"]

        def fetch(self, num, spec):
            return "OK", [(b"7 (BODY[] {10}", sample("10-staff-meeting.eml")), b")"]

        def store(self, num, op, flag):
            self.stored.append((num, op, flag))

    stub = Stub()
    assert poll_once(stub, "INBOX") == 1
    assert stub.stored == [(b"7", "+FLAGS", "\\Seen")]
    with session_scope() as db:
        from unhook.db import Report

        assert db.query(Report).count() == 1
