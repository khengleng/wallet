from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from wallets_demo.models import Tenant
from wallets_demo.saas import dispatch_pending_billing_events


class Command(BaseCommand):
    help = "Dispatch pending tenant billing webhook events."

    def add_arguments(self, parser):
        parser.add_argument("--tenant-code", help="Optional tenant code filter.")
        parser.add_argument("--limit", type=int, default=100, help="Maximum events to process.")

    def handle(self, *args, **options):
        tenant = None
        tenant_code = (options.get("tenant_code") or "").strip().lower()
        if tenant_code:
            tenant = Tenant.objects.filter(code=tenant_code).first()
            if tenant is None:
                raise CommandError("Tenant not found for --tenant-code.")
        result = dispatch_pending_billing_events(limit=max(1, int(options.get("limit") or 100)), tenant=tenant)
        self.stdout.write(
            self.style.SUCCESS(
                f"Dispatched tenant billing events: sent={result.sent} failed={result.failed} skipped={result.skipped}"
            )
        )
