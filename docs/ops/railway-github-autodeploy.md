# Railway GitHub Auto-Deploy Setup

This project should deploy from Railway directly on every push to `main` (no deploy hooks needed).

## 1) Connect each Railway service to GitHub source

In Railway dashboard, open each service:

- `Settings` -> `Source`
- Choose `Connect Repo`
- Repo: `khengleng/wallet`
- Branch: `main`
- Enable auto-deploy on push

## 2) Set root directory per service

Use these root directories:

- `web` -> `/`
- `api-gateway-service` -> `/services/api_gateway_service`
- `wallet-ledger-service` -> `/services/wallet_ledger_service`
- `identity-service` -> `/services/identity_service`
- `ops-risk-service` -> `/services/ops_risk_service`
- `audit-export-worker` -> `/services/audit_export_worker`
- `mobile-bff-service` -> `/services/mobile_bff_service`
- `ops-risk-consumer` -> `/services/ops_risk_consumer`
- `wallet-ledger-outbox-worker` -> `/services/wallet_ledger_outbox_worker`

Supporting services (`postgres`, `redis`, `rabbitmq`, `prometheus`, `grafana`, `keycloak`, `alertmanager`) do not deploy from this repository.

## 3) Keep GitHub Actions for smoke checks only

`railway-cicd.yml` is now manual smoke verification only and does not trigger deploy hooks.

Run manually when needed:

```bash
gh workflow run "Railway Smoke Verify (Manual)" -R khengleng/wallet
```

## 4) Verify deployment

- Railway service deployments should update automatically after push.
- Web app endpoint:
  - `/version` should show the latest release SHA.
