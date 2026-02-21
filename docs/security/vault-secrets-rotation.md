# Vault Integration and Secret Rotation Runbook

## Scope
Use HashiCorp Vault as source of truth for application secrets. Do not store long-lived secrets in source control.

## Secrets to Move to Vault First
- `DATABASE_URL`
- `JWT_SECRET`
- `SERVICE_API_KEY`
- `METRICS_TOKEN`
- `SIEM_SIGNING_SECRET`
- Keycloak client secrets

## Integration Pattern (Railway)
1. Store secrets in Vault KV v2.
2. Use CI/CD or a secure secret sync job to inject runtime env vars in Railway services.
3. Keep TTL-based short-lived credentials where possible.

## Runtime Secret Loading Contract
Services now support three secret sources in this order:
1. Direct env var (`KEY_NAME`)
2. File mount (`KEY_NAME_FILE`)
3. Vault lookup (`KEY_NAME_VAULT_PATH` + optional `KEY_NAME_VAULT_FIELD`)

Global Vault variables:
- `VAULT_ADDR`
- `VAULT_TOKEN`
- `VAULT_NAMESPACE` (optional)
- `VAULT_TIMEOUT_SECONDS` (optional, default `3`)

Examples:
- `INTERNAL_AUTH_SHARED_SECRET_VAULT_PATH=kv/data/wallet/prod`
- `INTERNAL_AUTH_SHARED_SECRET_VAULT_FIELD=internal_auth_shared_secret`
- `KEYCLOAK_CLIENT_SECRET_VAULT_PATH=kv/data/wallet/prod`
- `KEYCLOAK_CLIENT_SECRET_VAULT_FIELD=keycloak_client_secret`

## Rotation Policy
- Critical auth secrets: every 30 days.
- Database credentials: every 30-60 days.
- Immediate rotation after suspected compromise.

## Rotation Steps
1. Generate new secret in Vault.
2. Update dependent service variables in Railway.
3. Roll one service at a time.
4. Verify health/readiness and auth flows.
5. Invalidate old secret.

## Validation Checklist
- `/healthz` and `/readyz` pass on all services.
- Login/token issuance works.
- Metrics scraping still authenticated.
- No increase in 401/5xx after rollout.
