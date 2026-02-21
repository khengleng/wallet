import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'demo_project_app.settings')
django.setup()

from wallets_demo.models import ChartOfAccount, TreasuryAccount, User
from dj_wallet.models import Wallet
from wallets_demo.rbac import (
    DEFAULT_DEMO_ROLE_ASSIGNMENTS,
    assign_roles,
    seed_role_groups,
)

def setup():
    seed_role_groups()

    # Create superuser
    if not User.objects.filter(username='admin').exists():
        User.objects.create_superuser('admin', 'admin@example.com', 'admin123')
        print("Superuser created: admin / admin123")

    # Create demo users
    users = ['alice', 'bob', 'charlie']
    for username in users:
        if not User.objects.filter(username=username).exists():
            user = User.objects.create_user(username=username, password='password123')
            print(f"User created: {username}")
            
            # Initial deposit
            user.deposit(1000)
            print(f"Deposited 1000 to {username}'s wallet. Balance: {user.balance}")

    # Assign demo roles
    for username, roles in DEFAULT_DEMO_ROLE_ASSIGNMENTS.items():
        user = User.objects.filter(username=username).first()
        if user:
            assign_roles(user, roles)
            print(f"Assigned roles to {username}: {', '.join(roles)}")

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
            print(f"Treasury account created: {name} ({currency}) balance={balance}")

    coa_defaults = [
        ("1010", "Cash and Bank", "asset"),
        ("1020", "Treasury Float", "asset"),
        ("2010", "Customer Wallet Liability", "liability"),
        ("3010", "Owner Equity", "equity"),
        ("4010", "Platform Fee Revenue", "revenue"),
        ("5010", "Operations Expense", "expense"),
    ]
    for code, name, account_type in coa_defaults:
        coa, created = ChartOfAccount.objects.get_or_create(
            code=code,
            defaults={
                "name": name,
                "account_type": account_type,
                "currency": "USD",
                "is_active": True,
            },
        )
        if created:
            print(f"COA created: {coa.code} {coa.name} ({coa.account_type})")

if __name__ == '__main__':
    setup()
