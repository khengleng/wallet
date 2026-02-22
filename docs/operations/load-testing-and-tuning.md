# Load Testing and Tuning Runbook

## Goal
Establish a repeatable baseline for throughput/latency and tune service/database settings for high daily transaction volume.

## Tooling
- k6 scripts:
  - `scripts/loadtest/k6_gateway_baseline.js`
  - `scripts/loadtest/k6_gateway_spike.js`

## Prerequisites
- A test environment with production-like instance sizes.
- One valid JWT bearer token and one funded account ID.
- Prometheus + Grafana + Alertmanager active.

## Baseline Test
Run steady load first:

```bash
k6 run \
  -e BASE_URL=https://<gateway-domain> \
  -e BEARER_TOKEN=<jwt> \
  -e ACCOUNT_ID=<uuid> \
  scripts/loadtest/k6_gateway_baseline.js
```

## Spike Test
Run burst profile after baseline:

```bash
k6 run \
  -e BASE_URL=https://<gateway-domain> \
  -e BEARER_TOKEN=<jwt> \
  -e ACCOUNT_ID=<uuid> \
  scripts/loadtest/k6_gateway_spike.js
```

## Tuning Knobs
Tune in this order while re-running the same tests:

## One-Command Suite
Run baseline + spike and store summaries under `scripts/loadtest/results/<timestamp>/`:

```bash
BASE_URL=https://<gateway-domain> \
BEARER_TOKEN=<jwt> \
ACCOUNT_ID=<uuid> \
bash scripts/loadtest/run_gateway_suite.sh
```

1. API gateway
   - `RATE_LIMIT_*` values per endpoint tier
   - `LEDGER_MAX_RETRIES`
   - `LEDGER_CIRCUIT_FAILURE_THRESHOLD`
   - `LEDGER_CIRCUIT_RESET_SECONDS`
2. Ledger service
   - Worker/process count (`WEB_CONCURRENCY`, `GUNICORN_THREADS` where applicable)
   - DB connection pool size (via SQLAlchemy engine options)
3. PostgreSQL
   - CPU/memory tier
   - max connections
   - autovacuum thresholds and checkpoint settings
4. Redis/RabbitMQ
   - memory policy/limits
   - queue depth and consumer prefetch (`EVENT_CONSUMER_PREFETCH`)

## Success Criteria (Initial)
- p95 latency < 400ms under baseline profile
- p99 latency < 900ms under baseline profile
- error rate < 1%
- no sustained growth in dead-letter metrics

## Automated Release Gate
Use the summary validator to enforce deploy blocking thresholds:

```bash
python3 scripts/loadtest/validate_slo_gate.py \
  --baseline-summary scripts/loadtest/results/<timestamp>/baseline-summary.json \
  --spike-summary scripts/loadtest/results/<timestamp>/spike-summary.json
```

Defaults:
- baseline: `p95<400ms`, `p99<900ms`, `error_rate<0.01`
- spike: `p95<500ms`, `p99<1200ms`, `error_rate<0.02`

GitHub Actions workflow:
- `.github/workflows/performance-release-gate.yml`
- requires repository secrets:
  - `PERF_BASE_URL`
  - `PERF_BEARER_TOKEN`
  - `PERF_ACCOUNT_ID`
- optional evidence metrics secrets:
  - `EVIDENCE_GATEWAY_METRICS_URL`
  - `EVIDENCE_LEDGER_METRICS_URL`
  - `EVIDENCE_OPS_RISK_METRICS_URL`
  - `EVIDENCE_AUDIT_EXPORT_METRICS_URL`
  - `EVIDENCE_METRICS_TOKEN`

## Post-Deploy Smoke Checks
Run health/readiness checks across core services after every deployment:

```bash
python3 scripts/ops/post_deploy_smoke_check.py
```

GitHub Actions workflow:
- `.github/workflows/post-deploy-smoke-check.yml`
- required repository secrets:
  - `SMOKE_WEB_BASE_URL`
  - `SMOKE_GATEWAY_BASE_URL`
  - `SMOKE_LEDGER_BASE_URL`
  - `SMOKE_IDENTITY_BASE_URL`
  - `SMOKE_OPS_RISK_BASE_URL`
  - `SMOKE_AUDIT_EXPORT_BASE_URL`

## Failover Drill Automation
Manual failover drill workflow:
- `.github/workflows/failover-drill.yml`

Behavior:
- Runs pre-failover smoke checks.
- Runs pre-failover transaction probe (`scripts/ops/transaction_probe.py`).
- Executes `FAILOVER_DRILL_COMMAND` if configured.
- Runs post-failover smoke checks and post-failover transaction probe.
- Uploads evidence artifacts.

Required secrets:
- `SMOKE_WEB_BASE_URL`
- `SMOKE_GATEWAY_BASE_URL`
- `SMOKE_LEDGER_BASE_URL`
- `SMOKE_IDENTITY_BASE_URL`
- `SMOKE_OPS_RISK_BASE_URL`
- `SMOKE_AUDIT_EXPORT_BASE_URL`
- `PERF_BEARER_TOKEN`
- `PERF_ACCOUNT_ID`

Optional secret:
- `FAILOVER_DRILL_COMMAND` (service restart/failover command in staging)

## Capacity Planning Notes
- 1,000,000 transactions/day is roughly 11.6 tx/s average.
- Design for burst at least 20x average (>230 tx/s) plus safety headroom.
- Validate failover behavior during load: restart one service at a time and confirm no data loss.
