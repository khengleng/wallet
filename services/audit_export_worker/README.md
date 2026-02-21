# Audit Export Worker

SIEM export pipeline for `wallets_demo_backofficeauditlog`.

## Features
- Incremental export from Django audit table to SIEM webhook.
- HMAC-signed payloads (`X-Audit-Export-*` headers).
- Retry with exponential backoff + dead-letter persistence.
- Replay command for dead letters.
- Prometheus metrics endpoint for alerting/dashboard.

## Required Env Vars
- `DATABASE_URL`
- `SIEM_WEBHOOK_URL`
- `SIEM_SIGNING_SECRET`
- `METRICS_TOKEN` (required in production for `/metrics`)

## Optional Env Vars
- `SERVICE_NAME` (default `audit-export-worker`)
- `SIEM_TIMEOUT_SECONDS` (default `10`)
- `EXPORT_BATCH_SIZE` (default `200`)
- `EXPORT_POLL_INTERVAL_SECONDS` (default `2`)
- `EXPORT_MAX_ATTEMPTS` (default `20`)
- `EXPORT_RETRY_BASE_SECONDS` (default `2`)
- `EXPORT_REPLAY_BATCH_SIZE` (default `100`)

## Run Locally
```bash
cd services/audit_export_worker
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8080
```

Replay dead letters manually:
```bash
python -m app.replay_dead_letters --limit 200
```

## Metrics Auth
- `GET /metrics` accepts:
  - `Authorization: Bearer <METRICS_TOKEN>` (recommended)
  - `X-Metrics-Token: <METRICS_TOKEN>` (legacy compatibility)
