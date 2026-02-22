from __future__ import annotations

from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.db.models import Q
from django.utils import timezone

from wallets_demo.models import OperationCase, OperationCaseNote, TransactionMonitoringAlert, User


class Command(BaseCommand):
    help = "Escalate overdue operation cases based on SLA due-at timestamp."

    def add_arguments(self, parser):
        parser.add_argument("--actor-username", required=True)
        parser.add_argument("--fallback-sla-hours", type=int, default=24)
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, **options):
        actor = User.objects.filter(username=options["actor_username"]).first()
        if actor is None:
            raise CommandError("Actor user not found.")

        now = timezone.now()
        fallback_hours = max(1, int(options["fallback_sla_hours"]))
        cutoff = now - timedelta(hours=fallback_hours)
        dry_run = bool(options["dry_run"])

        overdue_cases = OperationCase.objects.filter(
            status__in=(
                OperationCase.STATUS_OPEN,
                OperationCase.STATUS_IN_PROGRESS,
            )
        ).filter(
            Q(sla_due_at__isnull=False, sla_due_at__lt=now)
            | Q(sla_due_at__isnull=True, created_at__lt=cutoff)
        )

        count = 0
        for case in overdue_cases.select_related("assigned_to", "merchant", "customer"):
            note = (
                f"Auto-escalated case {case.case_no} due to SLA breach. "
                f"status={case.status}"
            )
            if dry_run:
                self.stdout.write(f"DRY-RUN escalate case_id={case.id} case_no={case.case_no}")
                count += 1
                continue
            with transaction.atomic():
                case.status = OperationCase.STATUS_ESCALATED
                case.save(update_fields=["status", "updated_at"])
                OperationCaseNote.objects.create(
                    case=case,
                    note=note,
                    is_internal=True,
                    created_by=actor,
                )
                alert_exists = TransactionMonitoringAlert.objects.filter(
                    alert_type="case_sla_breach",
                    case=case,
                    status__in=(
                        TransactionMonitoringAlert.STATUS_OPEN,
                        TransactionMonitoringAlert.STATUS_IN_REVIEW,
                    ),
                ).exists()
                if not alert_exists:
                    TransactionMonitoringAlert.objects.create(
                        alert_type="case_sla_breach",
                        severity="high" if case.priority in {"high", "critical"} else "medium",
                        user=case.customer,
                        merchant=case.merchant,
                        case=case,
                        status=TransactionMonitoringAlert.STATUS_OPEN,
                        note=f"SLA breach for case {case.case_no}"[:255],
                        created_by=actor,
                        assigned_to=case.assigned_to,
                    )
                count += 1

        self.stdout.write(f"Escalated operation cases: {count} (dry_run={dry_run})")
