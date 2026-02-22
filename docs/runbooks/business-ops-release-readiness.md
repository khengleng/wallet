# Business Ops Release Readiness

This runbook defines the release gate for business operations services.

## Required Checks

1. Migrations applied on target environment (`python manage.py migrate --noinput`).
2. RBAC permissions reseeded (`python manage.py seed_rbac`).
3. Database isolation validation passed (`python scripts/ops/check_db_isolation.py`).
4. Release readiness snapshot executed from Operations Center:
   - `pending_refunds == 0` (or approved exception)
   - `failed_payouts == 0` (or approved exception)
   - `open_recon_breaks == 0` (or approved exception)
   - `open_high_alerts == 0` (or approved exception)
   - Automation equivalent:
     - `python manage.py release_readiness_gate` (fails with non-zero exit when gate fails)
     - `python manage.py release_readiness_gate --json` (machine-readable output)
5. Keycloak hardening check passes:
   - `python manage.py check_keycloak_hardening`
6. Metrics endpoint healthy and scraped:
   - `wallet_ops_*` metrics present.
7. Smoke tests pass:
   - `wallets_demo.tests.CustomerCIFWalletManagementTests`
   - `wallets_demo.tests.MerchantEnterpriseOperationsTests`
   - `wallets_demo.tests.MerchantOpsWorkflowTests`
   - `wallets_demo.tests.OperationalHardeningTests`

## Scheduled Business Automation Jobs

1. Settlement lifecycle automation
   - `python manage.py automate_settlements --actor-username <ops_user>`
   - Optional payout creation:
   - `python manage.py automate_settlements --actor-username <ops_user> --create-payouts`
2. Dispute SLA escalation
   - `python manage.py escalate_refund_disputes --actor-username <ops_user>`
3. Accounting period governance
   - Close:
   - `python manage.py manage_accounting_period --actor-username <finance_user> --period-start YYYY-MM-DD --period-end YYYY-MM-DD --currency USD --action close`
   - Re-open:
   - `python manage.py manage_accounting_period --actor-username <finance_user> --period-start YYYY-MM-DD --period-end YYYY-MM-DD --currency USD --action open`

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
