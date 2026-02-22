# API Gateway Service

JWT-authenticated gateway in front of `wallet-ledger-service`.

## Responsibilities
- Verify bearer JWT on all `/v1/*` operations (`AUTH_MODE=local_jwt` or `AUTH_MODE=keycloak_oidc`).
- Apply per-IP and per-user rate limiting.
- Forward validated requests to ledger using internal auth (`api_key` or signed HMAC headers).
- Emit audit logs for auth failures and transaction attempts.
- Expose mobile channel passthrough routes under `/mobile/v1/*` to `mobile-bff-service`.

## Required Env Vars
- `ENVIRONMENT=production`
- `AUTH_MODE` (`local_jwt` default, `keycloak_oidc` for Keycloak introspection)
- If `AUTH_MODE=local_jwt`:
  - `JWT_SECRET`
  - `JWT_ALGORITHM` (default `HS256`)
  - `JWT_AUDIENCE`
  - `JWT_ISSUER`
- If `AUTH_MODE=keycloak_oidc`:
  - `IDENTITY_SERVICE_BASE_URL` (e.g. `https://identity.example.com`)
  - `IDENTITY_SERVICE_API_KEY`
  - `IDENTITY_SERVICE_TIMEOUT_SECONDS` (default `3.0`)
  - `JWT_AUDIENCE` (expected audience claim)
- Mobile channel upstream:
  - `MOBILE_BFF_BASE_URL` (e.g. `https://mobile-bff-service-...`)
  - `MOBILE_BFF_TIMEOUT_SECONDS` (default `8.0`)
  - `MOBILE_BFF_SERVICE_API_KEY` (must match mobile-bff `SERVICE_API_KEY`; optional if not used)
- `LEDGER_BASE_URL` (for Railway use internal domain when possible)
- Internal service auth:
  - `INTERNAL_AUTH_MODE` (`api_key` or `hmac`)
  - if `api_key`: `LEDGER_API_KEY` (must match ledger `SERVICE_API_KEY`)
  - if `hmac`: `INTERNAL_AUTH_SHARED_SECRET` (must match ledger)
- `LEDGER_TIMEOUT_SECONDS` (default `10`)
- `LEDGER_MAX_RETRIES` (default `2`)
- `LEDGER_RETRY_BACKOFF_SECONDS` (default `0.2`)
- `LEDGER_CIRCUIT_FAILURE_THRESHOLD` (default `5`)
- `LEDGER_CIRCUIT_RESET_SECONDS` (default `30`)
- `METRICS_TOKEN` (required in production for `/metrics`)
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
- Distributed rate limiting (recommended for multi-replica production):
  - `RATE_LIMIT_BACKEND=redis`
  - `REDIS_URL=redis://<host>:6379/0`
- Step-up MFA on critical operations:
  - `STEP_UP_MFA_ENABLED=true`
  - `STEP_UP_MFA_CRITICAL_PATHS=/v1/transactions/withdraw,/v1/transactions/transfer`
  - `STEP_UP_MFA_AMR_VALUES=mfa,otp,totp,webauthn`
  - `STEP_UP_MFA_ACR_VALUES=2,urn:mace:incommon:iap:silver`

## Run Locally
```bash
cd services/api_gateway_service
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8082
```

## Mobile Channel Routes
- `POST /mobile/v1/auth/oidc/token`
- `POST /mobile/v1/auth/recovery/password-reset-url`
- `GET /mobile/v1/bootstrap`
- `GET /mobile/v1/profile`
- `POST /mobile/v1/profile`
- `GET /mobile/v1/personalization`
- `POST /mobile/v1/personalization/signals`
- `GET /mobile/v1/personalization/ai`
- `POST /mobile/v1/onboarding/self`
- `GET /mobile/v1/wallets/balance`
- `GET /mobile/v1/wallets/statement`
- `POST /mobile/v1/sessions/register`
- `GET /mobile/v1/sessions/active`
- `POST /mobile/v1/sessions/revoke`

## Metrics
- `wallet_gateway_waf_blocked_total` increments when requests are blocked by WAF deny rules.
- Auth: set `Authorization: Bearer <METRICS_TOKEN>` or `X-Metrics-Token: <METRICS_TOKEN>`.
