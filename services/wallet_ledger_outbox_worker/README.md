# Wallet Ledger Outbox Worker

Background relay worker for publishing ledger outbox events.

## Capabilities
- Claims pending outbox events with `FOR UPDATE SKIP LOCKED`
- Publishes to RabbitMQ exchange
- Retries with exponential backoff
- Dead-letters after configured max attempts

## Run Locally
```bash
cd services/wallet_ledger_service
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m app.outbox_worker
```

## Required Env Vars
- `DATABASE_URL`
- `ENVIRONMENT`
- `BROKER_URL` (AMQP URL for outbox relay, e.g. RabbitMQ)
- `OUTBOX_EXCHANGE` (default `wallet.events`)
- `OUTBOX_EXCHANGE_TYPE` (default `topic`)
- `OUTBOX_ROUTING_KEY_PREFIX` (default `ledger`)

## Database Migration
Run schema migration as a separate command before starting traffic:

```bash
python -m app.migrate
```

## Railway Deployment (Standalone Service)
1. Create a dedicated Railway service for ledger.
2. Set the service **Root Directory** to `services/wallet_ledger_service`.
3. Ensure the service uses Nixpacks (it will pick up local `nixpacks.toml`).
4. Set service variables:
   - `DATABASE_URL` (PostgreSQL connection string)
   - `ENVIRONMENT=production`
   - `SERVICE_API_KEY=<strong-random-secret>`
5. Run migration command:
   - `python -m app.migrate`
6. Deploy and verify:
   - `GET /healthz`
   - `GET /readyz`

## Worker
Run with:
```bash
python -m app.outbox_worker
```

See contracts in `docs/contracts/wallet-ledger-events.md`.
