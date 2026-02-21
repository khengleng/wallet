# Business Ops Release Readiness

This runbook defines the release gate for business operations services.

## Required Checks

1. Migrations applied on target environment (`python manage.py migrate --noinput`).
2. RBAC permissions reseeded (`python manage.py seed_rbac`).
3. Release readiness snapshot executed from Operations Center:
   - `pending_refunds == 0` (or approved exception)
   - `failed_payouts == 0` (or approved exception)
   - `open_recon_breaks == 0` (or approved exception)
   - `open_high_alerts == 0` (or approved exception)
4. Metrics endpoint healthy and scraped:
   - `wallet_ops_*` metrics present.
5. Smoke tests pass:
   - `wallets_demo.tests.CustomerCIFWalletManagementTests`
   - `wallets_demo.tests.MerchantEnterpriseOperationsTests`
   - `wallets_demo.tests.MerchantOpsWorkflowTests`
   - `wallets_demo.tests.OperationalHardeningTests`

## Rollback Triggers

1. Reconciliation break spike after release.
2. Payouts transition to `failed` after release.
3. Chargeback workflow cannot progress status updates.
4. Journal posting blocked unexpectedly by period-close controls.

## Emergency Actions

1. Freeze settlement payouts in Operations Center.
2. Open incident case and assign risk + operations.
3. Run targeted backfill/reconciliation.
4. Restore previous release if issue is systemic.
