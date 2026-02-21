# Identity Service

Dedicated identity boundary for OIDC and session/device lifecycle.

## Capabilities
- Keycloak token introspection proxy with short cache.
- OIDC helper endpoints (auth URL, code exchange, userinfo, logout URL).
- Device/session registration, listing, and revoke APIs.
- Password reset URL helper for account recovery flow.

## Required Env Vars
- `ENVIRONMENT=production`
- `DATABASE_ISOLATION_MODE` (`strict` in production)
- `IDENTITY_DATABASE_URL`
- `SERVICE_API_KEY` (required for `/v1/*` endpoints)
- `METRICS_TOKEN` (required in production for `/metrics`)
- `KEYCLOAK_BASE_URL`
- `KEYCLOAK_REALM`
- `KEYCLOAK_CLIENT_ID`
- `KEYCLOAK_CLIENT_SECRET`

## Run Locally
```bash
cd services/identity_service
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8085
```

## Internal APIs
- `POST /v1/tokens/introspect`
- `POST /v1/oidc/auth-url`
- `POST /v1/oidc/token`
- `POST /v1/oidc/userinfo`
- `POST /v1/oidc/logout-url`
- `POST /v1/sessions/register`
- `GET /v1/sessions/active?subject=<sub>`
- `POST /v1/sessions/revoke`
- `POST /v1/recovery/password-reset-url`
