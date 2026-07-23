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
  LOGSINK_ADMIN_EMAILS       comma-separated Entra identities allowed to use the
                             admin UI/endpoints via the gate's X-Auth-Request-Email
                             header (NOTE: the claim is preferred_username — the
                             UPN — not necessarily a personal email address)
  LOGSINK_ADMIN_TOKEN        alternative machine auth (Bearer) for scripts;
                             with BOTH this and LOGSINK_ADMIN_EMAILS unset the
                             admin endpoints answer 503 (fail closed)
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
from fastapi.responses import HTMLResponse

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
        self.admin_emails = {
            e.strip().lower()
            for e in _env("LOGSINK_ADMIN_EMAILS", "").split(",")
            if e.strip()
        }
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
        if "device" in entry:
            line["device"] = str(entry["device"])
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
    # Two accepted identities, fail closed when neither is configured:
    #  1. An Entra identity forwarded by the gate (X-Auth-Request-Email; the
    #     Traefik /admin router MUST stay Entra-gated — the forwardAuth
    #     overwrites this header, so it cannot be forged from outside).
    #  2. A machine Bearer token for scripts (price-tracker D-24 pattern).
    if not state.admin_emails and state.admin_token is None:
        raise HTTPException(status_code=503, detail="admin disabled")
    email = (request.headers.get("x-auth-request-email") or "").strip().lower()
    if email and email in state.admin_emails:
        return
    if state.admin_token is not None:
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer ") and hmac.compare_digest(
            state.admin_token, auth[7:].strip()
        ):
            return
    raise HTTPException(status_code=401, detail="not authorized for admin")


_ADMIN_PAGE = """<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>logsink admin</title>
<style>
  body { font: 16px/1.5 system-ui, sans-serif; background: #101418; color: #e6e8eb;
         max-width: 560px; margin: 2rem auto; padding: 0 1rem; }
  h1 { font-size: 1.2rem; } .who { color: #8a939e; font-size: .85rem; }
  .app { display: flex; align-items: center; justify-content: space-between;
         gap: .75rem; padding: .8rem 0; border-bottom: 1px solid #232a31; flex-wrap: wrap; }
  .name { font-weight: 600; }
  button { font: inherit; padding: .35rem .8rem; border-radius: .5rem; cursor: pointer;
           border: 1px solid #39424c; background: #1a2027; color: #e6e8eb; }
  button.on { background: #2f6fed; border-color: #2f6fed; color: #fff; }
  #err { color: #ff7a7a; }
</style>
<h1>logsink admin <span class="who" id="who"></span></h1>
<p class="who">Levels are runtime state — a shim redeploy falls back to the env seed.</p>
<div id="apps">loading…</div>
<p id="err"></p>
<script>
const LEVELS = ["DEBUG", "INFO", "WARN", "ERROR"];
async function refresh() {
  const r = await fetch("/admin/levels");
  if (!r.ok) { document.getElementById("err").textContent = "load failed: " + r.status; return; }
  const levels = await r.json();
  const root = document.getElementById("apps");
  root.innerHTML = "";
  for (const [app, level] of Object.entries(levels)) {
    const row = document.createElement("div"); row.className = "app";
    const name = document.createElement("span"); name.className = "name"; name.textContent = app;
    row.appendChild(name);
    const btns = document.createElement("span");
    for (const l of LEVELS) {
      const b = document.createElement("button");
      b.textContent = l;
      if (l === level) b.className = "on";
      b.onclick = async () => {
        const resp = await fetch("/admin/level/" + encodeURIComponent(app), {
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ level: l }),
        });
        document.getElementById("err").textContent = resp.ok ? "" : "save failed: " + resp.status;
        refresh();
      };
      btns.appendChild(b);
    }
    row.appendChild(btns);
    root.appendChild(row);
  }
}
refresh();
</script>
"""


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request) -> HTMLResponse:
    _require_admin(request)
    return HTMLResponse(_ADMIN_PAGE)


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
