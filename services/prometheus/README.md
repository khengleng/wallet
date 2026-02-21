# Prometheus Service

Prometheus for platform metrics collection and alert-rule evaluation.

## Railway Root Directory
Set the Railway service root to:

`services/prometheus`

## Required Env Vars
- `LEDGER_METRICS_TARGET` (example `wallet-ledger-service.railway.internal:8080`)
- `GATEWAY_METRICS_TARGET` (example `api-gateway-service.railway.internal:8080`)
- `OPS_RISK_METRICS_TARGET` (example `ops-risk-service.railway.internal:8080`)
- `AUDIT_EXPORT_METRICS_TARGET` (example `audit-export-worker.railway.internal:8080`)

## Optional Env Vars
- `PROM_SCRAPE_INTERVAL` (default `15s`)
- `PROM_EVAL_INTERVAL` (default `15s`)
