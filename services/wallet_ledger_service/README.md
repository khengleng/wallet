# Wallet Ledger Service

Standalone microservice for wallet accounting and transfers.

## Capabilities
- Transactional deposits, withdrawals, transfers
- Row-level locking for race-condition safety
- Idempotency-Key support on write endpoints
- Immutable ledger entry writes
- Outbox event writes in the same DB transaction

## Run Locally
```bash
cd services/wallet_ledger_service
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8080
```

## Required Env Vars
- `DATABASE_URL`
- `ENVIRONMENT`
- `SECRET_KEY` (for platform-level secret hygiene; this service itself does not issue auth tokens)

## Railway Deployment (Standalone Service)
1. Create a dedicated Railway service for ledger.
2. Set the service **Root Directory** to `services/wallet_ledger_service`.
3. Ensure the service uses Nixpacks (it will pick up local `nixpacks.toml`).
4. Set service variables:
   - `DATABASE_URL` (PostgreSQL connection string)
   - `ENVIRONMENT=production`
5. Deploy and verify:
   - `GET /healthz`
   - `GET /readyz`

## API
- `POST /v1/accounts`
- `GET /v1/accounts/{account_id}`
- `POST /v1/transactions/deposit` (requires `Idempotency-Key`)
- `POST /v1/transactions/withdraw` (requires `Idempotency-Key`)
- `POST /v1/transactions/transfer` (requires `Idempotency-Key`)

See contracts in `docs/contracts/wallet-ledger-events.md`.
