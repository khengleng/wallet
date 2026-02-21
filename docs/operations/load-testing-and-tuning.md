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

## Capacity Planning Notes
- 1,000,000 transactions/day is roughly 11.6 tx/s average.
- Design for burst at least 20x average (>230 tx/s) plus safety headroom.
- Validate failover behavior during load: restart one service at a time and confirm no data loss.
