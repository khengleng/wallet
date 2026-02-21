import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'demo_project_app.settings')
django.setup()

from wallets_demo.models import User
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

if __name__ == '__main__':
    setup()
