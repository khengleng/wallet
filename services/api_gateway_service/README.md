# API Gateway Service

JWT-authenticated gateway in front of `wallet-ledger-service`.

## Responsibilities
- Verify bearer JWT on all `/v1/*` operations.
- Apply per-IP and per-user rate limiting.
- Forward validated requests to ledger with internal `X-Service-Api-Key`.
- Emit audit logs for auth failures and transaction attempts.

## Required Env Vars
- `ENVIRONMENT=production`
- `JWT_SECRET`
- `JWT_ALGORITHM` (default `HS256`)
- `JWT_AUDIENCE`
- `JWT_ISSUER`
- `LEDGER_BASE_URL` (for Railway use internal domain when possible)
- `LEDGER_API_KEY` (must match ledger `SERVICE_API_KEY`)
- `RATE_LIMIT_PER_IP` (default `120/minute`)
- `RATE_LIMIT_PER_USER` (default `240/minute`)

## Run Locally
```bash
cd services/api_gateway_service
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8082
```
