from __future__ import annotations

from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from wallets_demo.models import (
    JournalEntryApproval,
    ReconciliationBreak,
    SettlementException,
    TransactionMonitoringAlert,
    User,
)


class Command(BaseCommand):
    help = (
        "Escalate stale back-office work queue items into monitoring alerts "
        "(journal approvals, settlement exceptions, reconciliation breaks)."
    )

    def add_arguments(self, parser):
        parser.add_argument("--actor-username", required=True)
        parser.add_argument("--journal-hours", type=int, default=8)
        parser.add_argument("--settlement-exception-hours", type=int, default=12)
        parser.add_argument("--reconciliation-break-hours", type=int, default=12)
        parser.add_argument("--dry-run", action="store_true")

    def _create_alert_if_missing(
        self,
        *,
        actor: User,
        alert_type: str,
        note: str,
        severity: str,
        user=None,
        merchant=None,
        dry_run: bool,
    ) -> bool:
        existing = TransactionMonitoringAlert.objects.filter(
            alert_type=alert_type,
            note=note,
            status__in=(
                TransactionMonitoringAlert.STATUS_OPEN,
                TransactionMonitoringAlert.STATUS_IN_REVIEW,
            ),
        ).exists()
        if existing:
            return False
        if dry_run:
            return True
        TransactionMonitoringAlert.objects.create(
            alert_type=alert_type,
            severity=severity,
            status=TransactionMonitoringAlert.STATUS_OPEN,
            user=user,
            merchant=merchant,
            note=note[:255],
            created_by=actor,
        )
        return True

    def handle(self, *args, **options):
        actor = User.objects.filter(username=options["actor_username"]).first()
        if actor is None:
            raise CommandError("Actor user not found.")

        now = timezone.now()
        dry_run = bool(options["dry_run"])
        journal_cutoff = now - timedelta(hours=max(1, int(options["journal_hours"])))
        settlement_cutoff = now - timedelta(
            hours=max(1, int(options["settlement_exception_hours"]))
        )
        recon_cutoff = now - timedelta(
            hours=max(1, int(options["reconciliation_break_hours"]))
        )

        journal_count = 0
        settlement_count = 0
        recon_count = 0

        stale_journal = JournalEntryApproval.objects.select_related(
            "entry", "maker", "source_entry"
        ).filter(
            status=JournalEntryApproval.STATUS_PENDING,
            created_at__lt=journal_cutoff,
        )
        for approval in stale_journal:
            note = (
                f"SLA breach: journal approval #{approval.id} "
                f"entry={approval.entry.entry_no} type={approval.request_type}"
            )
            with transaction.atomic():
                created = self._create_alert_if_missing(
                    actor=actor,
                    alert_type="journal_approval_sla",
                    note=note,
                    severity="high",
                    user=approval.maker,
                    dry_run=dry_run,
                )
            if created:
                journal_count += 1

        stale_exceptions = SettlementException.objects.select_related(
            "settlement",
            "settlement__merchant",
            "payout",
            "payout__settlement",
            "payout__settlement__merchant",
            "batch_file",
            "created_by",
        ).filter(
            status__in=(SettlementException.STATUS_OPEN, SettlementException.STATUS_IN_REVIEW),
            created_at__lt=settlement_cutoff,
        )
        for ex in stale_exceptions:
            merchant = None
            if ex.settlement_id:
                merchant = ex.settlement.merchant
            elif ex.payout_id and ex.payout.settlement_id:
                merchant = ex.payout.settlement.merchant
            note = (
                f"SLA breach: settlement exception #{ex.id} "
                f"reason={ex.reason_code} severity={ex.severity}"
            )
            with transaction.atomic():
                created = self._create_alert_if_missing(
                    actor=actor,
                    alert_type="settlement_exception_sla",
                    note=note,
                    severity="high" if ex.severity in {"high", "critical"} else "medium",
                    user=ex.created_by,
                    merchant=merchant,
                    dry_run=dry_run,
                )
            if created:
                settlement_count += 1

        stale_recon = ReconciliationBreak.objects.select_related(
            "merchant",
            "created_by",
            "run",
        ).filter(
            status__in=(ReconciliationBreak.STATUS_OPEN, ReconciliationBreak.STATUS_IN_REVIEW),
            created_at__lt=recon_cutoff,
        )
        for br in stale_recon:
            note = (
                f"SLA breach: reconciliation break #{br.id} "
                f"run={br.run.run_no} category={br.break_category}"
            )
            with transaction.atomic():
                created = self._create_alert_if_missing(
                    actor=actor,
                    alert_type="reconciliation_break_sla",
                    note=note,
                    severity="high" if br.status == ReconciliationBreak.STATUS_IN_REVIEW else "medium",
                    user=br.created_by,
                    merchant=br.merchant,
                    dry_run=dry_run,
                )
            if created:
                recon_count += 1

        self.stdout.write(
            "Escalation summary: "
            f"journal={journal_count}, settlement_exceptions={settlement_count}, "
            f"reconciliation_breaks={recon_count}, dry_run={dry_run}"
        )
