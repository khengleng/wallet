"""
Pytest configuration and fixtures for django_wallets tests.
"""

import os
import sys
from decimal import Decimal

import django
import pytest

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def pytest_configure():
    """Configure Django settings before running tests."""
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")
    django.setup()


# ============================================================================
# User Fixtures
# ============================================================================


@pytest.fixture()
def user_factory(db):
    """Factory for creating test users."""
    from tests.test_app.models import User

    def create_user(username=None, **kwargs):
        if username is None:
            import uuid

            username = f"user_{uuid.uuid4().hex[:8]}"
        return User.objects.create_user(
            username=username,
            email=f"{username}@example.com",
            password="testpass123",
            **kwargs,
        )

    return create_user


@pytest.fixture()
def user(user_factory):
    """Create a single test user."""
    return user_factory()


@pytest.fixture()
def user_with_balance(user_factory):
    """Create a test user with initial wallet balance."""

    def create_user_with_balance(amount=Decimal("100.00"), **kwargs):
        from django_wallets.services import WalletService

        user = user_factory(**kwargs)
        WalletService.deposit(user.wallet, amount, meta={"source": "test_fixture"})
        return user

    return create_user_with_balance


# ============================================================================
# Wallet Fixtures
# ============================================================================


@pytest.fixture()
def wallet(user):
    """Get or create the default wallet for a test user."""
    return user.wallet


@pytest.fixture()
def wallet_factory(user_factory):
    """Factory for creating wallets with specific slugs."""

    def create_wallet(holder=None, slug="default", **meta):
        if holder is None:
            holder = user_factory()
        if slug == "default":
            return holder.wallet
        return holder.create_wallet(slug, **meta)

    return create_wallet


@pytest.fixture()
def funded_wallet(wallet):
    """A wallet with 100.00 balance."""
    from django_wallets.services import WalletService

    WalletService.deposit(wallet, Decimal("100.00"))
    wallet.refresh_from_db()
    return wallet


# ============================================================================
# Organization Fixtures
# ============================================================================


@pytest.fixture()
def organization_factory(db):
    """Factory for creating test organizations."""
    from tests.test_app.models import Organization

    def create_org(name=None, **kwargs):
        if name is None:
            import uuid

            name = f"Org_{uuid.uuid4().hex[:8]}"
        return Organization.objects.create(name=name, **kwargs)

    return create_org


# ============================================================================
# Product Fixtures
# ============================================================================


@pytest.fixture()
def product_factory(db):
    """Factory for creating test products."""
    from tests.test_app.models import Product

    def create_product(name=None, price=Decimal("25.00"), stock=100, **kwargs):
        if name is None:
            import uuid

            name = f"Product_{uuid.uuid4().hex[:8]}"
        return Product.objects.create(name=name, price=price, stock=stock, **kwargs)

    return create_product


@pytest.fixture()
def product(product_factory):
    """A simple test product priced at 25.00."""
    return product_factory()


@pytest.fixture()
def digital_product_factory(db, user_factory):
    """Factory for creating digital products with wallets."""
    from tests.test_app.models import DigitalProduct

    def create_digital_product(
        name=None, price=Decimal("10.00"), seller=None, **kwargs
    ):
        if name is None:
            import uuid

            name = f"Digital_{uuid.uuid4().hex[:8]}"
        if seller is None:
            seller = user_factory()
        return DigitalProduct.objects.create(
            name=name, price=price, seller=seller, **kwargs
        )

    return create_digital_product


# ============================================================================
# Transaction Fixtures
# ============================================================================


@pytest.fixture()
def deposit_factory(wallet_factory):
    """Factory for creating deposit transactions."""
    from django_wallets.services import WalletService

    def create_deposit(wallet=None, amount=Decimal("100.00"), **kwargs):
        if wallet is None:
            wallet = wallet_factory()
        return WalletService.deposit(wallet, amount, **kwargs)

    return create_deposit


@pytest.fixture()
def withdrawal_factory(user_with_balance):
    """Factory for creating withdrawal transactions."""
    from django_wallets.services import WalletService

    def create_withdrawal(user=None, amount=Decimal("50.00"), **kwargs):
        if user is None:
            user = user_with_balance(Decimal("200.00"))
        return WalletService.withdraw(user.wallet, amount, **kwargs)

    return create_withdrawal


# ============================================================================
# Transfer Fixtures
# ============================================================================


@pytest.fixture()
def transfer_factory(user_with_balance, user_factory):
    """Factory for creating transfer records."""
    from django_wallets.services import TransferService

    def create_transfer(sender=None, recipient=None, amount=Decimal("50.00"), **kwargs):
        if sender is None:
            sender = user_with_balance(Decimal("200.00"))
        if recipient is None:
            recipient = user_factory()
        return TransferService.transfer(sender, recipient, amount, **kwargs)

    return create_transfer


# ============================================================================
# Signal Testing Fixtures
# ============================================================================


@pytest.fixture()
def signal_receiver():
    """Helper fixture for testing signals."""

    class SignalReceiver:
        def __init__(self):
            self.calls = []
            self.last_sender = None
            self.last_kwargs = None

        def __call__(self, sender, **kwargs):
            self.calls.append((sender, kwargs))
            self.last_sender = sender
            self.last_kwargs = kwargs

        @property
        def call_count(self):
            return len(self.calls)

        @property
        def was_called(self):
            return len(self.calls) > 0

        def reset(self):
            self.calls = []
            self.last_sender = None
            self.last_kwargs = None

    return SignalReceiver()
