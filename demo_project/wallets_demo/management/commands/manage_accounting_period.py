from __future__ import annotations

from datetime import date
from decimal import Decimal

from django.core.management.base import BaseCommand, CommandError
from django.db.models import Sum
from django.utils import timezone

from wallets_demo.models import AccountingPeriodClose, JournalEntry, JournalLine, User


class Command(BaseCommand):
    help = "Open/close accounting periods with governance checks."

    def add_arguments(self, parser):
        parser.add_argument("--actor-username", required=True)
        parser.add_argument("--period-start", required=True, help="YYYY-MM-DD")
        parser.add_argument("--period-end", required=True, help="YYYY-MM-DD")
        parser.add_argument("--currency", required=True)
        parser.add_argument("--action", choices=("close", "open"), default="close")
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, **options):
        actor = User.objects.filter(username=options["actor_username"]).first()
        if actor is None:
            raise CommandError("Actor user not found.")

        period_start = date.fromisoformat(options["period_start"])
        period_end = date.fromisoformat(options["period_end"])
        if period_start > period_end:
            raise CommandError("period-start cannot be after period-end.")

        currency = options["currency"].upper()
        action = options["action"]
        is_close = action == "close"

        if is_close:
            draft_count = JournalEntry.objects.filter(
                currency=currency,
                status=JournalEntry.STATUS_DRAFT,
                created_at__date__gte=period_start,
                created_at__date__lte=period_end,
            ).count()
            if draft_count > 0:
                raise CommandError(
                    f"Cannot close period: {draft_count} draft journal entries exist in range."
                )

            posted_qs = JournalLine.objects.filter(
                entry__currency=currency,
                entry__status=JournalEntry.STATUS_POSTED,
                entry__created_at__date__gte=period_start,
                entry__created_at__date__lte=period_end,
            )
            totals = posted_qs.aggregate(total_debit=Sum("debit"), total_credit=Sum("credit"))
            total_debit = totals.get("total_debit") or Decimal("0")
            total_credit = totals.get("total_credit") or Decimal("0")
            if total_debit != total_credit:
                raise CommandError(
                    f"Cannot close period: trial balance mismatch debit={total_debit} credit={total_credit}."
                )

        if options["dry_run"]:
            self.stdout.write(
                f"DRY-RUN accounting period action={action} {period_start}..{period_end} {currency}"
            )
            return

        period, created = AccountingPeriodClose.objects.get_or_create(
            period_start=period_start,
            period_end=period_end,
            currency=currency,
            defaults={
                "created_by": actor,
                "is_closed": is_close,
                "closed_by": actor if is_close else None,
                "closed_at": timezone.now() if is_close else None,
            },
        )
        if not created:
            period.is_closed = is_close
            period.closed_by = actor if is_close else None
            period.closed_at = timezone.now() if is_close else None
            period.save(update_fields=["is_closed", "closed_by", "closed_at", "updated_at"])

        self.stdout.write(
            f"Accounting period {'closed' if is_close else 'opened'}: {period_start}..{period_end} {currency}"
        )
