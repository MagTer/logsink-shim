import json

import httpx
import pytest
from fastapi.testclient import TestClient

import logsink_shim.app as shim


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("LOGSINK_KEYS", "sekret1:retro-fm,sekret2:other-app")
    monkeypatch.setenv("LOGSINK_ADMIN_TOKEN", "admintoken")
    monkeypatch.setenv("LOGSINK_LEVELS", '{"other-app": "ERROR"}')
    shim.state = shim.State()
    return TestClient(shim.app)


@pytest.fixture()
def captured_vl(monkeypatch):
    """Capture what would be forwarded to VictoriaLogs."""
    captured = {}

    class FakeAsyncClient:
        def __init__(self, *a, **kw): ...
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        async def post(self, url, params=None, content=b"", headers=None):
            captured["url"] = url
            captured["params"] = params
            captured["lines"] = [json.loads(l) for l in content.decode().splitlines()]
            return httpx.Response(200)

    monkeypatch.setattr(shim.httpx, "AsyncClient", FakeAsyncClient)
    return captured


def auth(key="sekret1"):
    return {"Authorization": f"Bearer {key}"}


def test_rejects_missing_and_unknown_keys(client):
    assert client.post("/ingest", content=b"x").status_code == 401
    assert client.post("/ingest", content=b"x", headers=auth("wrong")).status_code == 401


def test_ingest_stamps_app_server_side(client, captured_vl):
    batch = json.dumps({"msg": "hello", "level": "INFO", "app": "spoofed"})
    resp = client.post("/ingest", content=batch, headers=auth())
    assert resp.status_code == 204
    assert captured_vl["lines"][0]["app"] == "retro-fm"
    assert captured_vl["params"]["_stream_fields"] == "app"


def test_device_field_passes_through(client, captured_vl):
    batch = json.dumps({"msg": "hi", "level": "ERROR", "device": "Volvo XC60"})
    assert client.post("/ingest", content=batch, headers=auth()).status_code == 204
    assert captured_vl["lines"][0]["device"] == "Volvo XC60"


def test_drops_lines_below_configured_level(client, captured_vl):
    batch = "\n".join(
        json.dumps(e)
        for e in [
            {"msg": "debugline", "level": "DEBUG"},
            {"msg": "errorline", "level": "ERROR"},
        ]
    )
    resp = client.post("/ingest", content=batch, headers=auth("sekret2"))  # other-app: ERROR
    assert resp.status_code == 204
    msgs = [l["_msg"] for l in captured_vl["lines"]]
    assert msgs == ["errorline"]


def test_quota_429s_only_the_flooding_app(client, captured_vl):
    shim.state.rate, shim.state.burst = 0.0, 2.0
    shim.state.buckets = {}
    line = json.dumps({"msg": "x", "level": "ERROR"})
    assert client.post("/ingest", content=line, headers=auth()).status_code == 204
    assert client.post("/ingest", content=line, headers=auth()).status_code == 204
    resp = client.post("/ingest", content=line, headers=auth())
    assert resp.status_code == 429
    assert resp.headers["Retry-After"]
    # other-app has its own bucket and is unaffected
    assert client.post("/ingest", content=line, headers=auth("sekret2")).status_code == 204


def test_config_returns_per_app_level(client):
    assert client.get("/ingest/config", headers=auth()).json() == {
        "app": "retro-fm",
        "level": "INFO",
    }
    assert client.get("/ingest/config", headers=auth("sekret2")).json()["level"] == "ERROR"


def test_admin_fails_closed_without_token_and_emails(client, monkeypatch):
    monkeypatch.delenv("LOGSINK_ADMIN_TOKEN", raising=False)
    monkeypatch.delenv("LOGSINK_ADMIN_EMAILS", raising=False)
    shim.state = shim.State()
    resp = TestClient(shim.app).put(
        "/admin/level/retro-fm",
        json={"level": "DEBUG"},
        headers=auth("anything"),
    )
    assert resp.status_code == 503


def test_admin_accepts_gate_forwarded_email(client, monkeypatch):
    monkeypatch.setenv("LOGSINK_ADMIN_EMAILS", "Operator@Example.COM")
    shim.state = shim.State()
    c = TestClient(shim.app)
    ok = c.put(
        "/admin/level/retro-fm",
        json={"level": "DEBUG"},
        headers={"X-Auth-Request-Email": "operator@example.com"},
    )
    assert ok.status_code == 200
    denied = c.put(
        "/admin/level/retro-fm",
        json={"level": "DEBUG"},
        headers={"X-Auth-Request-Email": "intruder@example.com"},
    )
    assert denied.status_code == 401


def test_admin_page_served_to_gated_email(client, monkeypatch):
    monkeypatch.setenv("LOGSINK_ADMIN_EMAILS", "operator@example.com")
    shim.state = shim.State()
    resp = TestClient(shim.app).get(
        "/admin", headers={"X-Auth-Request-Email": "operator@example.com"}
    )
    assert resp.status_code == 200
    assert "logsink admin" in resp.text


def test_admin_sets_level_used_by_config(client):
    resp = client.put(
        "/admin/level/retro-fm",
        json={"level": "DEBUG"},
        headers=auth("admintoken"),
    )
    assert resp.status_code == 200
    assert client.get("/ingest/config", headers=auth()).json()["level"] == "DEBUG"
    assert client.put(
        "/admin/level/retro-fm", json={"level": "NOPE"}, headers=auth("admintoken")
    ).status_code == 400
