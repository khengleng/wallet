"""
Unit tests for ExchangeService.

Tests for exchanging funds between wallets of the same holder.
"""

from decimal import Decimal

import pytest

from dj_wallet.exceptions import InsufficientFunds, WalletException
from dj_wallet.services import ExchangeService, WalletService


@pytest.mark.django_db()
class TestExchangeService:
    """Tests for ExchangeService.exchange()."""

    def test_exchange_basic_1_to_1(self, user_factory):
        """Basic exchange at 1:1 rate should move funds between wallets."""
        user = user_factory()

        # Create wallets
        usd_wallet = user.wallet  # default wallet
        eur_wallet = user.create_wallet("eur")

        # Fund USD wallet
        WalletService.deposit(usd_wallet, Decimal("100.00"))

        # Exchange USD to EUR
        ExchangeService.exchange(user, "default", "eur", Decimal("50.00"))

        usd_wallet.refresh_from_db()
        eur_wallet.refresh_from_db()

        assert usd_wallet.balance == Decimal("50.00")
        assert eur_wallet.balance == Decimal("50.00")

    def test_exchange_with_rate(self, user_factory):
        """Exchange with rate should apply conversion."""
        user = user_factory()

        usd_wallet = user.wallet
        eur_wallet = user.create_wallet("eur")

        WalletService.deposit(usd_wallet, Decimal("100.00"))

        # Exchange 50 USD to EUR at 0.85 rate
        ExchangeService.exchange(
            user, "default", "eur", Decimal("50.00"), rate=Decimal("0.85")
        )

        usd_wallet.refresh_from_db()
        eur_wallet.refresh_from_db()

        assert usd_wallet.balance == Decimal("50.00")
        assert eur_wallet.balance == Decimal("42.50")  # 50 * 0.85

    def test_exchange_rate_greater_than_1(self, user_factory):
        """Exchange with rate > 1 should increase amount."""
        user = user_factory()

        usd_wallet = user.wallet
        jpy_wallet = user.create_wallet("jpy")

        WalletService.deposit(usd_wallet, Decimal("100.00"))

        # Exchange 10 USD to JPY at 150 rate
        ExchangeService.exchange(
            user, "default", "jpy", Decimal("10.00"), rate=Decimal("150")
        )

        usd_wallet.refresh_from_db()
        jpy_wallet.refresh_from_db()

        assert usd_wallet.balance == Decimal("90.00")
        assert jpy_wallet.balance == Decimal("1500.00")  # 10 * 150

    def test_exchange_insufficient_funds(self, user_factory):
        """Exchange with insufficient funds should raise InsufficientFunds."""
        user = user_factory()

        usd_wallet = user.wallet
        user.create_wallet("eur")

        WalletService.deposit(usd_wallet, Decimal("50.00"))

        with pytest.raises(InsufficientFunds):
            ExchangeService.exchange(user, "default", "eur", Decimal("100.00"))

    def test_exchange_default_rate(self, user_factory):
        """Exchange with no rate should default to 1.0."""
        user = user_factory()

        wallet1 = user.wallet
        wallet2 = user.create_wallet("secondary")

        WalletService.deposit(wallet1, Decimal("100.00"))

        ExchangeService.exchange(user, "default", "secondary", Decimal("25.00"))

        wallet1.refresh_from_db()
        wallet2.refresh_from_db()

        assert wallet1.balance == Decimal("75.00")
        assert wallet2.balance == Decimal("25.00")  # 25 * 1.0

    def test_exchange_creates_transfer_record(self, user_factory):
        """Exchange should create a Transfer record."""
        from dj_wallet.models import Transfer

        user = user_factory()
        user.create_wallet("eur")

        WalletService.deposit(user.wallet, Decimal("100.00"))

        ExchangeService.exchange(user, "default", "eur", Decimal("50.00"))

        # Check transfer was created with exchange status
        transfer = Transfer.objects.filter(status=Transfer.STATUS_EXCHANGE).first()
        assert transfer is not None

    def test_exchange_full_balance(self, user_factory):
        """Exchange of full balance should leave source wallet at zero."""
        user = user_factory()

        wallet1 = user.wallet
        wallet2 = user.create_wallet("secondary")

        WalletService.deposit(wallet1, Decimal("100.00"))

        ExchangeService.exchange(user, "default", "secondary", Decimal("100.00"))

        wallet1.refresh_from_db()
        wallet2.refresh_from_db()

        assert wallet1.balance == Decimal("0")
        assert wallet2.balance == Decimal("100.00")

    def test_exchange_rejects_same_wallet(self, user_factory):
        """Exchange should fail when source and target wallets are identical."""
        user = user_factory()
        wallet = user.wallet
        WalletService.deposit(wallet, Decimal("100.00"))

        with pytest.raises(WalletException):
            ExchangeService.exchange(user, "default", "default", Decimal("10.00"))
