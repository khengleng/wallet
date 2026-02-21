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
