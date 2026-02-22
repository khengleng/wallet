from __future__ import annotations

from datetime import date, datetime, timedelta
from decimal import Decimal

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from wallets_demo.models import (
    MerchantCashflowEvent,
    MerchantSettlementRecord,
    SettlementPayout,
    User,
)


def _parse_date(value: str | None, default: date) -> date:
    if not value:
        return default
    return date.fromisoformat(value)


def _new_settlement_no() -> str:
    return f"SETTLE-{timezone.now().strftime('%Y%m%d%H%M%S%f')}"


def _new_payout_ref() -> str:
    return f"PAYOUT-{timezone.now().strftime('%Y%m%d%H%M%S%f')}"


class Command(BaseCommand):
    help = "Automatically create merchant settlements for unsettled cashflow events."

    def add_arguments(self, parser):
        parser.add_argument("--actor-username", required=True)
        parser.add_argument("--period-start", help="YYYY-MM-DD")
        parser.add_argument("--period-end", help="YYYY-MM-DD")
        parser.add_argument("--currency", help="Optional currency filter")
        parser.add_argument("--create-payouts", action="store_true")
        parser.add_argument("--dry-run", action="store_true")

    def handle(self, *args, **options):
        actor = User.objects.filter(username=options["actor_username"]).first()
        if actor is None:
            raise CommandError("Actor user not found.")

        today = timezone.localdate()
        period_start = _parse_date(options.get("period_start"), today - timedelta(days=1))
        period_end = _parse_date(options.get("period_end"), today)
        if period_start > period_end:
            raise CommandError("period-start cannot be after period-end.")

        qs = MerchantCashflowEvent.objects.filter(
            settled_at__isnull=True,
            created_at__date__gte=period_start,
            created_at__date__lte=period_end,
        ).order_by("merchant_id", "currency", "created_at", "id")
        if options.get("currency"):
            qs = qs.filter(currency=options["currency"].upper())

        grouped: dict[tuple[int, str], list[MerchantCashflowEvent]] = {}
        for evt in qs.select_related("merchant"):
            grouped.setdefault((evt.merchant_id, evt.currency), []).append(evt)

        created_count = 0
        payout_count = 0
        for (merchant_id, currency), events in grouped.items():
            existing = MerchantSettlementRecord.objects.filter(
                merchant_id=merchant_id,
                currency=currency,
                period_start=period_start,
                period_end=period_end,
            ).first()
            if existing:
                self.stdout.write(
                    f"SKIP existing settlement merchant_id={merchant_id} currency={currency} settlement_no={existing.settlement_no}"
                )
                continue
            gross_amount = sum((evt.amount for evt in events), Decimal("0.00"))
            fee_amount = sum((evt.fee_amount for evt in events), Decimal("0.00"))
            net_amount = sum((evt.net_amount for evt in events), Decimal("0.00"))

            if options["dry_run"]:
                self.stdout.write(
                    f"DRY-RUN settlement merchant_id={merchant_id} currency={currency} events={len(events)} net={net_amount}"
                )
                continue

            with transaction.atomic():
                settlement = MerchantSettlementRecord.objects.create(
                    merchant_id=merchant_id,
                    settlement_no=_new_settlement_no(),
                    currency=currency,
                    period_start=period_start,
                    period_end=period_end,
                    gross_amount=gross_amount,
                    fee_amount=fee_amount,
                    net_amount=net_amount,
                    event_count=len(events),
                    status=MerchantSettlementRecord.STATUS_POSTED,
                    created_by=actor,
                    approved_by=actor,
                    approved_at=timezone.now(),
                )
                MerchantCashflowEvent.objects.filter(id__in=[evt.id for evt in events]).update(
                    settlement_reference=settlement.settlement_no,
                    settled_at=timezone.now(),
                )
                created_count += 1

                if options["create_payouts"]:
                    SettlementPayout.objects.get_or_create(
                        settlement=settlement,
                        defaults={
                            "payout_reference": _new_payout_ref(),
                            "amount": settlement.net_amount,
                            "currency": settlement.currency,
                            "status": SettlementPayout.STATUS_PENDING,
                            "initiated_by": actor,
                        },
                    )
                    payout_count += 1

        self.stdout.write(
            f"Settlement automation completed: settlements={created_count}, payouts={payout_count}, dry_run={options['dry_run']}"
        )
