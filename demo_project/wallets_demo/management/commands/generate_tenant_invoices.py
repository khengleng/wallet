from __future__ import annotations

from datetime import date

from django.core.management.base import BaseCommand, CommandError

from wallets_demo.models import Tenant
from wallets_demo.saas import generate_tenant_invoice_for_period


class Command(BaseCommand):
    help = "Generate tenant invoices for a target period."

    def add_arguments(self, parser):
        parser.add_argument("--tenant-code", help="Optional tenant code filter.")
        parser.add_argument("--year", type=int, required=True, help="Invoice year (YYYY).")
        parser.add_argument("--month", type=int, required=True, help="Invoice month (1-12).")
        parser.add_argument("--draft", action="store_true", help="Generate as draft instead of issued.")

    def handle(self, *args, **options):
        year = int(options["year"])
        month = int(options["month"])
        if month < 1 or month > 12:
            raise CommandError("--month must be in range 1..12")
        period_start = date(year, month, 1)
        period_end = (
            date(year + 1, 1, 1) - date.resolution
            if month == 12
            else date(year, month + 1, 1) - date.resolution
        )
        tenant_code = (options.get("tenant_code") or "").strip().lower()
        tenants = Tenant.objects.filter(code=tenant_code) if tenant_code else Tenant.objects.filter(is_active=True)
        if tenant_code and not tenants.exists():
            raise CommandError("Tenant not found for --tenant-code.")
        for tenant in tenants.order_by("code"):
            invoice = generate_tenant_invoice_for_period(
                tenant=tenant,
                period_start=period_start,
                period_end=period_end,
                issue=not bool(options.get("draft")),
            )
            self.stdout.write(self.style.SUCCESS(f"{tenant.code}: {invoice.invoice_no} total={invoice.total_amount}"))
