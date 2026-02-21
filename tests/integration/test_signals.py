"""
Integration tests for Django signals.
"""

from decimal import Decimal

import pytest

from dj_wallet.services import TransferService, WalletService
from dj_wallet.signals import (
    balance_changed,
    pre_deposit,
    pre_withdraw,
    transaction_created,
    wallet_created,
)


@pytest.mark.django_db()
@pytest.mark.integration()
class TestSignalIntegration:
    """Tests for signal emission during wallet operations."""

    def test_balance_changed_receives_wallet(self, wallet, signal_receiver):
        """balance_changed signal should include wallet."""
        balance_changed.connect(signal_receiver)
        try:
            WalletService.deposit(wallet, Decimal("100.00"))

            assert signal_receiver.was_called
            assert "wallet" in signal_receiver.last_kwargs
            assert signal_receiver.last_kwargs["wallet"].pk == wallet.pk
        finally:
            balance_changed.disconnect(signal_receiver)

    def test_balance_changed_receives_transaction(self, wallet, signal_receiver):
        """balance_changed signal should include transaction."""
        balance_changed.connect(signal_receiver)
        try:
            WalletService.deposit(wallet, Decimal("100.00"))

            assert "transaction" in signal_receiver.last_kwargs
            txn = signal_receiver.last_kwargs["transaction"]
            assert txn.amount == Decimal("100.00")
        finally:
            balance_changed.disconnect(signal_receiver)

    def test_transaction_created_on_unconfirmed(self, wallet, signal_receiver):
        """transaction_created should fire even for unconfirmed transactions."""
        transaction_created.connect(signal_receiver)
        try:
            WalletService.deposit(wallet, Decimal("100.00"), confirmed=False)

            assert signal_receiver.was_called
            txn = signal_receiver.last_kwargs["transaction"]
            assert txn.confirmed is False
        finally:
            transaction_created.disconnect(signal_receiver)

    def test_multiple_handlers_all_called(self, wallet):
        """Multiple signal handlers should all be called."""
        call_order = []

        def handler1(sender, **kwargs):
            call_order.append("handler1")

        def handler2(sender, **kwargs):
            call_order.append("handler2")

        def handler3(sender, **kwargs):
            call_order.append("handler3")

        balance_changed.connect(handler1)
        balance_changed.connect(handler2)
        balance_changed.connect(handler3)

        try:
            WalletService.deposit(wallet, Decimal("100.00"))

            assert len(call_order) == 3
            assert "handler1" in call_order
            assert "handler2" in call_order
            assert "handler3" in call_order
        finally:
            balance_changed.disconnect(handler1)
            balance_changed.disconnect(handler2)
            balance_changed.disconnect(handler3)

    def test_signals_on_transfer(self, user_factory, signal_receiver):
        """Transfers should emit signals for both wallets."""
        sender = user_factory()
        recipient = user_factory()

        WalletService.deposit(sender.wallet, Decimal("100.00"))

        signal_receiver.reset()
        balance_changed.connect(signal_receiver)

        try:
            TransferService.transfer(sender, recipient, Decimal("50.00"))

            # Should have been called twice (withdraw + deposit)
            assert signal_receiver.call_count == 2
        finally:
            balance_changed.disconnect(signal_receiver)

    def test_no_balance_signal_on_unconfirmed(self, wallet, signal_receiver):
        """Unconfirmed transactions should not emit balance_changed."""
        balance_changed.connect(signal_receiver)

        try:
            WalletService.deposit(wallet, Decimal("100.00"), confirmed=False)

            assert not signal_receiver.was_called
        finally:
            balance_changed.disconnect(signal_receiver)

    def test_pre_deposit_signal_emitted(self, wallet, signal_receiver):
        """pre_deposit should be emitted before a deposit transaction."""
        pre_deposit.connect(signal_receiver)
        try:
            WalletService.deposit(wallet, Decimal("10.00"))
            assert signal_receiver.was_called
            assert signal_receiver.last_kwargs["wallet"].pk == wallet.pk
            assert signal_receiver.last_kwargs["amount"] == Decimal("10.00")
        finally:
            pre_deposit.disconnect(signal_receiver)

    def test_pre_withdraw_signal_emitted(self, funded_wallet, signal_receiver):
        """pre_withdraw should be emitted before a withdrawal transaction."""
        pre_withdraw.connect(signal_receiver)
        try:
            WalletService.withdraw(funded_wallet, Decimal("10.00"))
            assert signal_receiver.was_called
            assert signal_receiver.last_kwargs["wallet"].pk == funded_wallet.pk
            assert signal_receiver.last_kwargs["amount"] == Decimal("10.00")
        finally:
            pre_withdraw.disconnect(signal_receiver)

    def test_wallet_created_signal_emitted(self, user_factory, signal_receiver):
        """wallet_created should be emitted when a wallet is first persisted."""
        user = user_factory()
        wallet_created.connect(signal_receiver)
        try:
            _ = user.wallet
            assert signal_receiver.was_called
            assert signal_receiver.last_kwargs["wallet"].holder_id == user.pk
            assert signal_receiver.last_kwargs["holder"].pk == user.pk
        finally:
            wallet_created.disconnect(signal_receiver)
