"""Checks that only mean something on a real Postgres.

Everything else in the suite runs on SQLite. Set UNHOOK_TEST_POSTGRES_URL to a server where
the user may create databases (CI starts one) and these run; without it they are skipped.
"""

import os
import threading

import pytest
from conftest import SAMPLES
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url

from unhook import db, service

SERVER_URL = os.environ.get("UNHOOK_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(not SERVER_URL, reason="UNHOOK_TEST_POSTGRES_URL is not set")


def _driver(url) -> str:
    return url.set(drivername="postgresql+psycopg").render_as_string(hide_password=False)


@pytest.fixture
def scratch_url():
    """A throwaway, empty database, so every test starts from nothing like a first deploy."""
    base = make_url(SERVER_URL)
    admin = create_engine(_driver(base), isolation_level="AUTOCOMMIT")
    name = f"unhook_test_{os.getpid()}"
    with admin.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{name}"'))
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    yield _driver(base.set(database=name))
    with admin.connect() as conn:
        conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
    admin.dispose()


def test_processes_starting_together_can_all_create_the_schema(scratch_url):
    # The API, the worker and the mailbox poller boot at the same moment on a new database.
    starters = 6
    gate = threading.Barrier(starters)
    errors = []

    def boot():
        engine = create_engine(scratch_url)
        try:
            gate.wait()
            db.create_schema(engine)
        except Exception as exc:
            errors.append(exc)
        finally:
            engine.dispose()

    threads = [threading.Thread(target=boot) for _ in range(starters)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors[0]
    engine = create_engine(scratch_url)
    assert {"reports", "cases", "indicators"} <= set(inspect(engine).get_table_names())
    engine.dispose()


def test_a_report_goes_through_on_postgres(scratch_url):
    from fastapi.testclient import TestClient

    from unhook.api import create_app

    db.configure(scratch_url)
    service.default_services.cache_clear()
    try:
        client = TestClient(create_app())
        raw = (SAMPLES / "01-m365-password-expiry.eml").read_bytes()
        first = client.post("/api/reports", files={"file": ("m.eml", raw, "message/rfc822")}, data={"reporter": "a@org.example"})
        again = client.post("/api/reports", files={"file": ("m.eml", raw, "message/rfc822")}, data={"reporter": "b@org.example"})
        assert first.status_code == again.status_code == 202

        assert client.get(f"/api/reports/{first.json()['id']}").json()["verdict"] == "malicious"
        cases = client.get("/api/cases").json()
        assert cases["total"] == 1  # the second report joined the first case
        detail = client.get(f"/api/cases/{cases['items'][0]['id']}").json()
        assert detail["report_count"] == 2 and detail["analysis"]["findings"]
        assert "session-verify.example" in client.get("/api/blocklist/txt").text
    finally:
        db.configure("sqlite:///:memory:")
        service.default_services.cache_clear()
