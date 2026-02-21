# Monitoring Stack

This repository includes a local observability stack based on Prometheus + Grafana.

## Included Components
- Prometheus server (`http://localhost:9090`)
- Grafana server (`http://localhost:3000`)
- Alertmanager server (`http://localhost:9093`)
- Alerting rules:
  - `infra/monitoring/alerts/audit-export-alerts.yml`
  - `infra/monitoring/alerts/platform-alerts.yml`
- Dashboards:
  - `infra/monitoring/dashboards/audit-export-dashboard.json`
  - `infra/monitoring/dashboards/platform-overview-dashboard.json`

## Start Stack Locally
From the repository root:

```bash
docker compose -f infra/docker-compose.microservices.yml up -d --build
```

Access:
- Prometheus: `http://localhost:9090`
- Grafana: `http://localhost:3000` (username `admin`, password `admin`)

## Scrape Targets
Prometheus scrapes the following services on the internal compose network:
- `wallet-ledger-service:8080/metrics`
- `api-gateway-service:8080/metrics`
- `ops-risk-service:8080/metrics`
- `audit-export-worker:8080/metrics`

Config file:
- `infra/monitoring/prometheus/prometheus.yml`

## Railway Deployment Notes
Deploy two dedicated services from this repository:

1. Prometheus service
   - Root directory: `services/prometheus`
   - Internal port: `9090`
   - Required env vars:
      - `LEDGER_METRICS_TARGET=wallet-ledger-service.railway.internal:8080`
      - `GATEWAY_METRICS_TARGET=api-gateway-service.railway.internal:8080`
      - `OPS_RISK_METRICS_TARGET=ops-risk-service.railway.internal:8080`
      - `AUDIT_EXPORT_METRICS_TARGET=audit-export-worker.railway.internal:8080`
      - `METRICS_TOKEN=<shared-strong-token>`
      - `ALERTMANAGER_TARGET=alertmanager.railway.internal:9093`

2. Alertmanager service
   - Root directory: `services/alertmanager`
   - Internal port: `9093`
   - Optional env vars:
     - `ALERTMANAGER_WEBHOOK_URL=<your-webhook-url>`
     - `ALERTMANAGER_SLACK_WEBHOOK_URL=<your-slack-webhook>`
     - `ALERTMANAGER_SLACK_CHANNEL=#wallet-alerts`

3. Grafana service
   - Root directory: `services/grafana`
   - Internal port: `3000`
   - Required env vars:
     - `PROMETHEUS_URL=http://prometheus.railway.internal:9090`
     - `GF_SECURITY_ADMIN_USER=<your-admin-user>`
     - `GF_SECURITY_ADMIN_PASSWORD=<strong-password>`
     - `GF_USERS_ALLOW_SIGN_UP=false`

After deployment, open Grafana and confirm dashboards under folder `Wallet Platform`.
