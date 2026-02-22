from __future__ import annotations

from .models import (
    DisputeRefundRequest,
    ReconciliationBreak,
    SettlementPayout,
    TransactionMonitoringAlert,
)


def release_readiness_snapshot() -> dict:
    pending_refunds = DisputeRefundRequest.objects.filter(
        status=DisputeRefundRequest.STATUS_PENDING
    ).count()
    failed_payouts = SettlementPayout.objects.filter(
        status=SettlementPayout.STATUS_FAILED
    ).count()
    open_recon_breaks = ReconciliationBreak.objects.filter(
        status__in=[ReconciliationBreak.STATUS_OPEN, ReconciliationBreak.STATUS_IN_REVIEW]
    ).count()
    open_high_alerts = TransactionMonitoringAlert.objects.filter(
        status=TransactionMonitoringAlert.STATUS_OPEN,
        severity="high",
    ).count()

    checks = {
        "pending_refunds": pending_refunds,
        "failed_payouts": failed_payouts,
        "open_recon_breaks": open_recon_breaks,
        "open_high_alerts": open_high_alerts,
    }
    failed_checks = [name for name, value in checks.items() if value > 0]
    return {
        **checks,
        "is_ready": len(failed_checks) == 0,
        "failed_checks": failed_checks,
    }
