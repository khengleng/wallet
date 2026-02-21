# API Gateway Service

JWT-authenticated gateway in front of `wallet-ledger-service`.

## Responsibilities
- Verify bearer JWT on all `/v1/*` operations (`AUTH_MODE=local_jwt` or `AUTH_MODE=keycloak_oidc`).
- Apply per-IP and per-user rate limiting.
- Forward validated requests to ledger with internal `X-Service-Api-Key`.
- Emit audit logs for auth failures and transaction attempts.

## Required Env Vars
- `ENVIRONMENT=production`
- `AUTH_MODE` (`local_jwt` default, `keycloak_oidc` for Keycloak introspection)
- If `AUTH_MODE=local_jwt`:
  - `JWT_SECRET`
  - `JWT_ALGORITHM` (default `HS256`)
  - `JWT_AUDIENCE`
  - `JWT_ISSUER`
- If `AUTH_MODE=keycloak_oidc`:
  - `KEYCLOAK_BASE_URL` (e.g. `https://id.example.com`)
  - `KEYCLOAK_REALM`
  - `KEYCLOAK_CLIENT_ID`
  - `KEYCLOAK_CLIENT_SECRET`
  - `KEYCLOAK_INTROSPECTION_TIMEOUT_SECONDS` (default `2.0`)
  - `JWT_AUDIENCE` (expected audience claim)
- `LEDGER_BASE_URL` (for Railway use internal domain when possible)
- `LEDGER_API_KEY` (must match ledger `SERVICE_API_KEY`)
- `LEDGER_TIMEOUT_SECONDS` (default `10`)
- `LEDGER_MAX_RETRIES` (default `2`)
- `LEDGER_RETRY_BACKOFF_SECONDS` (default `0.2`)
- `LEDGER_CIRCUIT_FAILURE_THRESHOLD` (default `5`)
- `LEDGER_CIRCUIT_RESET_SECONDS` (default `30`)
- `RATE_LIMIT_PER_IP` (default `120/minute`)
- `RATE_LIMIT_PER_USER` (default `240/minute`)
- Tiered endpoint rate limits:
  - `RATE_LIMIT_READ_PER_IP` (default `300/minute`) for `GET /v1/accounts/{id}`
  - `RATE_LIMIT_READ_PER_USER` (default `600/minute`)
  - `RATE_LIMIT_WRITE_PER_IP` (default `120/minute`) for account create/deposit
  - `RATE_LIMIT_WRITE_PER_USER` (default `240/minute`)
  - `RATE_LIMIT_CRITICAL_PER_IP` (default `60/minute`) for withdraw/transfer
  - `RATE_LIMIT_CRITICAL_PER_USER` (default `120/minute`)
- WAF deny rules (optional):
  - `WAF_BLOCKED_IPS` comma-separated IPs (example `1.2.3.4,8.8.8.8`)
  - `WAF_BLOCKED_CIDRS` comma-separated CIDRs (example `10.0.0.0/8,203.0.113.0/24`)
  - `WAF_BLOCKED_USER_AGENTS` comma-separated case-insensitive substrings (example `sqlmap,curl/8.`)

## Run Locally
```bash
cd services/api_gateway_service
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8082
```

## Metrics
- `wallet_gateway_waf_blocked_total` increments when requests are blocked by WAF deny rules.
