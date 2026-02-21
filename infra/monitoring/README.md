# Monitoring Stack

This repository includes a local observability stack based on Prometheus + Grafana.

## Included Components
- Prometheus server (`http://localhost:9090`)
- Grafana server (`http://localhost:3000`)
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
- Deploy Prometheus and Grafana as separate services.
- Mount these files in each service:
  - Prometheus config: `infra/monitoring/prometheus/prometheus.yml`
  - Alerts: `infra/monitoring/alerts/*.yml`
  - Grafana provisioning: `infra/monitoring/grafana/provisioning/*`
  - Dashboards: `infra/monitoring/dashboards/*.json`
- Update scrape targets in Prometheus config to Railway internal hostnames.
- Set strong Grafana admin credentials in Railway env vars.
