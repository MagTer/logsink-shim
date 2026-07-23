"""logsink-shim — auth/quota edge in front of VictoriaLogs for app-development logs.

Sits behind Traefik's public protection chain on a path-scoped, non-Entra ingest
route (ADR-009-style exception). Everything it does:

  1. Validates per-app append keys (Bearer) and stamps the app name server-side
     as a VictoriaLogs stream field — clients cannot impersonate each other.
  2. Enforces a per-app token bucket so one flooding app 429s on its own quota
     instead of starving the others (storage-level caps are the last resort).
  3. Drops lines below the app's configured level (defense in depth — clients
     are told the level via GET /config and shouldn't send them at all).
  4. Serves the per-app log level, remotely adjustable via an admin endpoint
     that FAILS CLOSED (503) when no admin token is configured.

Config (env):
  LOGSINK_KEYS               "key1:app-one,key2:app-two"  (required for ingest)
  LOGSINK_VL_URL             default http://victorialogs-apps:9428
  LOGSINK_ADMIN_TOKEN        unset => admin endpoints answer 503 (fail closed)
  LOGSINK_DEFAULT_LEVEL      default INFO
  LOGSINK_LEVELS             optional seed, e.g. {"retro-fm": "DEBUG"}
  LOGSINK_RATE_LINES_PER_SEC default 50 (per app)
  LOGSINK_BURST_LINES        default 500 (per app)
  LOGSINK_MAX_BODY_BYTES     default 524288
"""

from __future__ import annotations

import hmac
import json
import os
import time

import httpx
from fastapi import FastAPI, HTTPException, Request, Response

LEVELS = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40}

app = FastAPI(title="logsink-shim", docs_url=None, redoc_url=None)


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


class State:
    def __init__(self) -> None:
        self.keys: dict[str, str] = {}
        for pair in _env("LOGSINK_KEYS", "").split(","):
            if ":" in pair:
                key, app_name = pair.split(":", 1)
                self.keys[key.strip()] = app_name.strip()
        self.vl_url = _env("LOGSINK_VL_URL", "http://victorialogs-apps:9428")
        self.admin_token = os.environ.get("LOGSINK_ADMIN_TOKEN") or None
        self.default_level = _env("LOGSINK_DEFAULT_LEVEL", "INFO").upper()
        self.levels: dict[str, str] = {
            k: str(v).upper()
            for k, v in json.loads(_env("LOGSINK_LEVELS", "{}")).items()
        }
        self.rate = float(_env("LOGSINK_RATE_LINES_PER_SEC", "50"))
        self.burst = float(_env("LOGSINK_BURST_LINES", "500"))
        self.max_body = int(_env("LOGSINK_MAX_BODY_BYTES", "524288"))
        # app -> (tokens, last_refill_monotonic)
        self.buckets: dict[str, tuple[float, float]] = {}

    def level_for(self, app_name: str) -> str:
        return self.levels.get(app_name, self.default_level)

    def take_tokens(self, app_name: str, n: int) -> bool:
        tokens, last = self.buckets.get(app_name, (self.burst, time.monotonic()))
        now = time.monotonic()
        tokens = min(self.burst, tokens + (now - last) * self.rate)
        if n > tokens:
            self.buckets[app_name] = (tokens, now)
            return False
        self.buckets[app_name] = (tokens - n, now)
        return True


state = State()


def _bearer(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer")
    return auth[7:].strip()


def _app_for_key(request: Request) -> str:
    key = _bearer(request)
    for known, app_name in state.keys.items():
        if hmac.compare_digest(known, key):
            return app_name
    raise HTTPException(status_code=401, detail="unknown key")


@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True}


@app.get("/ingest/config")
async def config(request: Request) -> dict:
    app_name = _app_for_key(request)
    return {"app": app_name, "level": state.level_for(app_name)}


@app.post("/ingest")
async def ingest(request: Request) -> Response:
    app_name = _app_for_key(request)
    body = await request.body()
    if len(body) > state.max_body:
        raise HTTPException(status_code=413, detail="batch too large")

    min_level = LEVELS.get(state.level_for(app_name), 20)
    out_lines: list[str] = []
    for raw in body.decode("utf-8", "replace").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            entry = {"msg": raw}
        level = str(entry.get("level", "INFO")).upper()
        if LEVELS.get(level, 20) < min_level:
            continue
        line = {
            "_msg": str(entry.get("msg", "")),
            "level": level,
            "app": app_name,  # stamped server-side; ignore any client claim
        }
        if "tag" in entry:
            line["tag"] = str(entry["tag"])
        if "ts" in entry:
            line["_time"] = entry["ts"]
        out_lines.append(json.dumps(line, ensure_ascii=False))

    if not out_lines:
        return Response(status_code=204)

    if not state.take_tokens(app_name, len(out_lines)):
        raise HTTPException(
            status_code=429,
            detail="quota exceeded",
            headers={"Retry-After": "30"},
        )

    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            resp = await client.post(
                f"{state.vl_url}/insert/jsonline",
                params={"_stream_fields": "app", "_msg_field": "_msg", "_time_field": "_time"},
                content="\n".join(out_lines).encode(),
                headers={"Content-Type": "application/stream+json"},
            )
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="log store unavailable")
    if resp.status_code >= 300:
        raise HTTPException(status_code=502, detail="log store rejected batch")
    return Response(status_code=204)


def _require_admin(request: Request) -> None:
    # Fail closed: without a configured admin token the endpoint is unusable,
    # never unauthenticated (same pattern as price-tracker's MCP bearer).
    if state.admin_token is None:
        raise HTTPException(status_code=503, detail="admin disabled")
    if not hmac.compare_digest(state.admin_token, _bearer(request)):
        raise HTTPException(status_code=401, detail="bad admin token")


@app.get("/admin/levels")
async def get_levels(request: Request) -> dict:
    _require_admin(request)
    apps = sorted(set(state.keys.values()))
    return {a: state.level_for(a) for a in apps}


@app.put("/admin/level/{app_name}")
async def set_level(app_name: str, request: Request) -> dict:
    _require_admin(request)
    payload = await request.json()
    level = str(payload.get("level", "")).upper()
    if level not in LEVELS:
        raise HTTPException(status_code=400, detail=f"level must be one of {sorted(LEVELS)}")
    state.levels[app_name] = level
    return {"app": app_name, "level": level}
