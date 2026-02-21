from __future__ import annotations

from decimal import Decimal

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction

from .fx_provider import fetch_fx_snapshot
from .models import FxRate, User


def sync_external_fx_rates(
    *,
    base_currency: str | None = None,
    quote_currencies: list[str] | None = None,
    actor: User | None = None,
) -> tuple[int, str]:
    base = (base_currency or getattr(settings, "PLATFORM_BASE_CURRENCY", "USD")).upper()
    supported = [c.upper() for c in getattr(settings, "SUPPORTED_CURRENCIES", ["USD"])]
    quotes = quote_currencies or [c for c in supported if c != base]
    if not quotes:
        raise ValidationError("No quote currencies to sync.")

    snapshot = fetch_fx_snapshot(base, quotes)
    created_count = 0
    with transaction.atomic():
        for quote, rate in snapshot.rates.items():
            if rate <= Decimal("0"):
                continue
            FxRate.objects.create(
                base_currency=base,
                quote_currency=quote,
                rate=rate,
                is_active=True,
                source_provider=snapshot.provider,
                source_reference=snapshot.source_reference,
                created_by=actor,
            )
            created_count += 1
    return created_count, snapshot.provider
