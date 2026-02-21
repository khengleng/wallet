# Ops & Risk Service

Event-driven consumer service for operational/risk workflows.

## Capabilities
- Idempotent event consumption (`processed_events` unique by `event_id`)
- Dead-letter capture for processing failures
- Replay tooling for pending dead letters
- Basic risk rule: high-value transaction alerting
- Health/readiness/metrics endpoints

## Run Locally
```bash
cd services/ops_risk_service
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m app.migrate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8080
```

Start consumer worker:
```bash
python -m app.consumer
```

Replay dead letters:
```bash
python -m app.replay_dead_letters --limit 200
```

## Required Env Vars
- `DATABASE_URL`
- `BROKER_URL`
- `EVENT_EXCHANGE_NAME` (default `wallet.events`)
- `EVENT_EXCHANGE_TYPE` (default `topic`)
- `EVENT_QUEUE_NAME` (default `ops_risk_events`)
- `EVENT_ROUTING_KEY` (default `ledger.#`)
- `RISK_HIGH_VALUE_THRESHOLD` (default `10000`)
