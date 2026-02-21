from __future__ import annotations

import json
from dataclasses import dataclass
from decimal import Decimal
from urllib.error import HTTPError
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
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "wallet-platform-fx-sync/1.0",
        },
    )
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


def _load_open_er_api(base_currency: str, quote_currencies: list[str]) -> FxSnapshot:
    base_url = getattr(settings, "FX_PROVIDER_BASE_URL", "https://open.er-api.com/v6")
    url = f"{base_url.rstrip('/')}/latest/{base_currency}"
    payload = _http_get_json(url)
    if payload.get("result") != "success":
        raise ValidationError(f"open_er_api returned non-success result: {payload.get('result')}")
    raw_rates = payload.get("rates") or {}
    rates = {
        ccy: Decimal(str(raw_rates[ccy]))
        for ccy in quote_currencies
        if ccy in raw_rates
    }
    return FxSnapshot(
        provider="open_er_api",
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
    fallback_provider = getattr(settings, "FX_PROVIDER_FALLBACK", "open_er_api").lower()
    if provider == "frankfurter":
        try:
            return _load_frankfurter(base, quotes)
        except HTTPError:
            if fallback_provider == "open_er_api":
                return _load_open_er_api(base, quotes)
            raise
    if provider == "open_er_api":
        return _load_open_er_api(base, quotes)
    raise ValidationError(f"Unsupported FX provider: {provider}")
