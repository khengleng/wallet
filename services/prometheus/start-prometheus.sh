#!/bin/sh
set -eu

SCRAPE_INTERVAL="${PROM_SCRAPE_INTERVAL:-15s}"
EVAL_INTERVAL="${PROM_EVAL_INTERVAL:-15s}"
LEDGER_TARGET="${LEDGER_METRICS_TARGET:-wallet-ledger-service.railway.internal:8080}"
GATEWAY_TARGET="${GATEWAY_METRICS_TARGET:-api-gateway-service.railway.internal:8080}"
OPS_RISK_TARGET="${OPS_RISK_METRICS_TARGET:-ops-risk-service.railway.internal:8080}"
AUDIT_TARGET="${AUDIT_EXPORT_METRICS_TARGET:-audit-export-worker.railway.internal:8080}"

cat > /etc/prometheus/prometheus.yml <<CONFIG
global:
  scrape_interval: ${SCRAPE_INTERVAL}
  evaluation_interval: ${EVAL_INTERVAL}

rule_files:
  - /etc/prometheus/alerts/*.yml

scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets: ["127.0.0.1:9090"]

  - job_name: wallet-ledger-service
    metrics_path: /metrics
    static_configs:
      - targets: ["${LEDGER_TARGET}"]

  - job_name: api-gateway-service
    metrics_path: /metrics
    static_configs:
      - targets: ["${GATEWAY_TARGET}"]

  - job_name: ops-risk-service
    metrics_path: /metrics
    static_configs:
      - targets: ["${OPS_RISK_TARGET}"]

  - job_name: audit-export-worker
    metrics_path: /metrics
    static_configs:
      - targets: ["${AUDIT_TARGET}"]
CONFIG

exec /bin/prometheus \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/prometheus \
  --web.enable-lifecycle
