from django.core.management.base import BaseCommand

from wallets_demo.models import ChartOfAccount, FxRate, TreasuryAccount


class Command(BaseCommand):
    help = "Seed baseline treasury accounts and chart of accounts for business operations."

    def handle(self, *args, **options):
        treasury_defaults = [
            ("operating-usd", "USD", 500000),
            ("settlement-usd", "USD", 200000),
            ("reserve-usd", "USD", 1000000),
        ]
        for name, currency, balance in treasury_defaults:
            account, created = TreasuryAccount.objects.get_or_create(
                name=name,
                defaults={"currency": currency, "balance": balance},
            )
            if created:
                self.stdout.write(f"Created treasury account: {account.name}")

        coa_defaults = [
            ("1010", "Cash and Bank", "asset"),
            ("1020", "Treasury Float", "asset"),
            ("2010", "Customer Wallet Liability", "liability"),
            ("3010", "Owner Equity", "equity"),
            ("4010", "Platform Fee Revenue", "revenue"),
            ("5010", "Operations Expense", "expense"),
        ]
        for code, name, account_type in coa_defaults:
            chart, created = ChartOfAccount.objects.get_or_create(
                code=code,
                defaults={
                    "name": name,
                    "account_type": account_type,
                    "currency": "USD",
                    "is_active": True,
                },
            )
            if created:
                self.stdout.write(f"Created COA account: {chart.code} {chart.name}")

        fx_defaults = [
            ("USD", "EUR", "0.92000000"),
            ("EUR", "USD", "1.08695652"),
            ("USD", "SGD", "1.35000000"),
            ("SGD", "USD", "0.74074074"),
            ("USD", "GBP", "0.79000000"),
            ("GBP", "USD", "1.26582278"),
        ]
        for base, quote, rate in fx_defaults:
            fx, created = FxRate.objects.get_or_create(
                base_currency=base,
                quote_currency=quote,
                defaults={"rate": rate, "is_active": True},
            )
            if created:
                self.stdout.write(f"Created FX rate: {base}/{quote}={rate}")

        self.stdout.write(self.style.SUCCESS("Business baseline seed complete."))
