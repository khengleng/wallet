import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'demo_project_app.settings')
django.setup()

from wallets_demo.models import User
from dj_wallet.models import Wallet

def setup():
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

if __name__ == '__main__':
    setup()
