#!/bin/sh
set -eu

SCRAPE_INTERVAL="${PROM_SCRAPE_INTERVAL:-15s}"
EVAL_INTERVAL="${PROM_EVAL_INTERVAL:-15s}"
LEDGER_TARGET="${LEDGER_METRICS_TARGET:-wallet-ledger-service.railway.internal:8080}"
GATEWAY_TARGET="${GATEWAY_METRICS_TARGET:-api-gateway-service.railway.internal:8080}"
OPS_RISK_TARGET="${OPS_RISK_METRICS_TARGET:-ops-risk-service.railway.internal:8080}"
AUDIT_TARGET="${AUDIT_EXPORT_METRICS_TARGET:-audit-export-worker.railway.internal:8080}"
ALERTMANAGER_TARGET="${ALERTMANAGER_TARGET:-alertmanager.railway.internal:9093}"
METRICS_TOKEN="${METRICS_TOKEN:-}"
WEB_LISTEN_PORT="${PORT:-9090}"

SCRAPE_AUTH_BLOCK=""
if [ -n "${METRICS_TOKEN}" ]; then
  SCRAPE_AUTH_BLOCK="
    authorization:
      type: Bearer
      credentials: ${METRICS_TOKEN}"
fi

cat > /etc/prometheus/prometheus.yml <<CONFIG
global:
  scrape_interval: ${SCRAPE_INTERVAL}
  evaluation_interval: ${EVAL_INTERVAL}

rule_files:
  - /etc/prometheus/alerts/*.yml

alerting:
  alertmanagers:
    - static_configs:
        - targets: ["${ALERTMANAGER_TARGET}"]

scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets: ["127.0.0.1:${WEB_LISTEN_PORT}"]

  - job_name: wallet-ledger-service
    metrics_path: /metrics${SCRAPE_AUTH_BLOCK}
    static_configs:
      - targets: ["${LEDGER_TARGET}"]

  - job_name: api-gateway-service
    metrics_path: /metrics${SCRAPE_AUTH_BLOCK}
    static_configs:
      - targets: ["${GATEWAY_TARGET}"]

  - job_name: ops-risk-service
    metrics_path: /metrics${SCRAPE_AUTH_BLOCK}
    static_configs:
      - targets: ["${OPS_RISK_TARGET}"]

  - job_name: audit-export-worker
    metrics_path: /metrics${SCRAPE_AUTH_BLOCK}
    static_configs:
      - targets: ["${AUDIT_TARGET}"]
CONFIG

exec /bin/prometheus \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/prometheus \
  --web.listen-address=":${WEB_LISTEN_PORT}" \
  --web.enable-lifecycle
