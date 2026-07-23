# logsink-shim

Tiny auth/quota edge that sits in front of a [VictoriaLogs](https://docs.victoriametrics.com/victorialogs/)
instance and makes it safe to expose a log-append endpoint to mobile/embedded apps
(Android phones, Android Automotive head units) that cannot complete an interactive
SSO login.

Deployed via the `home-server` repo (compose pins a tag of this image); this repo
only builds the image. See that repo's ADR for the deployment design.

## What it does

- **Per-app append keys** (Bearer): the app identity is stamped server-side as the
  VictoriaLogs stream field `app` — a client cannot impersonate another app.
- **Per-app token bucket**: a flooding app gets `429` on its own quota; other apps'
  budgets are untouched. Storage-level disk caps remain the last resort.
- **Per-app log level**: `GET /ingest/config` tells the client which levels to send;
  the shim also drops below-level lines server-side as defense in depth.
- **Remote level control**: `PUT /admin/level/{app}` guarded by a separate admin
  token that **fails closed** (503 when unset).

## API

| Method | Path                 | Auth         | Purpose                            |
|--------|----------------------|--------------|------------------------------------|
| POST   | `/ingest`            | app key      | Append NDJSON log lines            |
| GET    | `/ingest/config`     | app key      | Current log level for the app      |
| GET    | `/admin/levels`      | admin token  | All apps' levels                   |
| PUT    | `/admin/level/{app}` | admin token  | Set an app's level                 |
| GET    | `/healthz`           | none         | Liveness for the compose healthcheck |

Ingest body: one JSON object per line — `{"ts": <epoch-ms or RFC3339>, "level": "INFO", "tag": "PlayerManager", "msg": "..."}`.
Only `msg` is required.

## Configuration (env)

| Variable                     | Default                          |
|------------------------------|----------------------------------|
| `LOGSINK_KEYS`               | — (`key1:app-one,key2:app-two`)  |
| `LOGSINK_VL_URL`             | `http://victorialogs-apps:9428`  |
| `LOGSINK_ADMIN_TOKEN`        | unset → admin endpoints 503      |
| `LOGSINK_DEFAULT_LEVEL`      | `INFO`                           |
| `LOGSINK_LEVELS`             | `{}` (JSON seed, e.g. `{"retro-fm":"DEBUG"}`) |
| `LOGSINK_RATE_LINES_PER_SEC` | `50` per app                     |
| `LOGSINK_BURST_LINES`        | `500` per app                    |
| `LOGSINK_MAX_BODY_BYTES`     | `524288`                         |

## Development

```bash
pip install -e .[dev]
pytest
uvicorn logsink_shim.app:app --reload
```

Releases: push a `v*` tag → GitHub Actions runs tests and pushes
`ghcr.io/magter/logsink-shim:<tag>`.
