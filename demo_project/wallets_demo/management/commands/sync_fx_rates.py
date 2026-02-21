from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from wallets_demo.fx_sync import sync_external_fx_rates


class Command(BaseCommand):
    help = "Sync FX rates from configured international provider."

    def add_arguments(self, parser):
        parser.add_argument(
            "--base",
            default=getattr(settings, "PLATFORM_BASE_CURRENCY", "USD"),
            help="Base currency (default: PLATFORM_BASE_CURRENCY).",
        )
        parser.add_argument(
            "--quotes",
            default="",
            help="Comma-separated quote currencies (default: SUPPORTED_CURRENCIES excluding base).",
        )

    def handle(self, *args, **options):
        base = (options.get("base") or "USD").strip().upper()
        quotes_raw = (options.get("quotes") or "").strip()
        quotes = [x.strip().upper() for x in quotes_raw.split(",") if x.strip()] if quotes_raw else None
        try:
            count, provider = sync_external_fx_rates(
                base_currency=base,
                quote_currencies=quotes,
                actor=None,
            )
        except Exception as exc:
            raise CommandError(f"FX sync failed: {exc}") from exc
        self.stdout.write(self.style.SUCCESS(f"Synced {count} FX rates from {provider}."))
