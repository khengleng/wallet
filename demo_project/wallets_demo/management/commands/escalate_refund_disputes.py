from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from wallets_demo.models import DisputeRefundRequest, OperationCase, OperationCaseNote, Tenant, User


class Command(BaseCommand):
    help = "Escalate pending refund disputes whose SLA due time has passed."

    def add_arguments(self, parser):
        parser.add_argument("--actor-username", required=True)
        parser.add_argument("--tenant-code", help="Optional tenant code; defaults to actor tenant.")
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, **options):
        actor = User.objects.filter(username=options["actor_username"]).first()
        if actor is None:
            raise CommandError("Actor user not found.")
        tenant_code = (options.get("tenant_code") or "").strip().lower()
        tenant = None
        if tenant_code:
            tenant = Tenant.objects.filter(code__iexact=tenant_code, is_active=True).first()
            if tenant is None:
                raise CommandError("Tenant not found for --tenant-code.")
        elif actor.tenant_id:
            tenant = actor.tenant

        now = timezone.now()
        overdue = DisputeRefundRequest.objects.select_related("case").filter(
            status=DisputeRefundRequest.STATUS_PENDING,
            sla_due_at__isnull=False,
            sla_due_at__lt=now,
            escalated_at__isnull=True,
        )
        if tenant is not None:
            overdue = overdue.filter(merchant__tenant=tenant)
        count = 0
        for refund in overdue:
            if options["dry_run"]:
                self.stdout.write(f"DRY-RUN escalate refund_id={refund.id} case={refund.case.case_no}")
                count += 1
                continue
            with transaction.atomic():
                refund.escalated_at = now
                refund.escalation_reason = "SLA breach"
                refund.save(update_fields=["escalated_at", "escalation_reason"])
                refund.case.status = OperationCase.STATUS_ESCALATED
                refund.case.save(update_fields=["status", "updated_at"])
                OperationCaseNote.objects.create(
                    case=refund.case,
                    note=f"Auto-escalated refund request #{refund.id} due to SLA breach.",
                    is_internal=True,
                    created_by=actor,
                )
                count += 1

        self.stdout.write(f"Escalated refunds: {count} (dry_run={options['dry_run']})")
