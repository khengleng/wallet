from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from django.conf import settings
from django.core.exceptions import ValidationError


@dataclass(frozen=True)
class FxSnapshot:
    provider: str
    base_currency: str
    rates: dict[str, Decimal]
    source_reference: str


def _http_get_json(url: str) -> dict:
    request = Request(url, headers={"Accept": "application/json"})
    timeout = getattr(settings, "FX_PROVIDER_TIMEOUT_SECONDS", 10)
    with urlopen(request, timeout=timeout) as response:
        payload = response.read().decode("utf-8")
    return json.loads(payload)


def _load_frankfurter(base_currency: str, quote_currencies: list[str]) -> FxSnapshot:
    symbols = ",".join(quote_currencies)
    params = urlencode({"from": base_currency, "to": symbols})
    base_url = getattr(settings, "FX_PROVIDER_BASE_URL", "https://api.frankfurter.app")
    url = f"{base_url.rstrip('/')}/latest?{params}"
    payload = _http_get_json(url)
    rates = {
        ccy.upper(): Decimal(str(rate))
        for ccy, rate in (payload.get("rates") or {}).items()
    }
    return FxSnapshot(
        provider="frankfurter",
        base_currency=base_currency,
        rates=rates,
        source_reference=url,
    )


def fetch_fx_snapshot(base_currency: str, quote_currencies: list[str]) -> FxSnapshot:
    base = base_currency.upper()
    quotes = [c.upper() for c in quote_currencies if c.upper() != base]
    if not quotes:
        raise ValidationError("No quote currencies were provided.")

    provider = getattr(settings, "FX_PROVIDER", "frankfurter").lower()
    if provider == "frankfurter":
        return _load_frankfurter(base, quotes)
    raise ValidationError(f"Unsupported FX provider: {provider}")
