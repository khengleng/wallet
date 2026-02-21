# Grafana Service

Grafana with pre-provisioned Prometheus datasource and wallet dashboards.

## Railway Root Directory
Set the Railway service root to:

`services/grafana`

## Required Env Vars
- `PROMETHEUS_URL` (example `http://prometheus.railway.internal:9090`)
- `GF_SECURITY_ADMIN_USER` (recommended non-default)
- `GF_SECURITY_ADMIN_PASSWORD` (strong password required)

## Optional Env Vars
- `GF_USERS_ALLOW_SIGN_UP=false`
