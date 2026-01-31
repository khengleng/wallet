"""
Tests for transaction status and confirmation workflow.
"""

from decimal import Decimal

import pytest

from dj_wallet.exceptions import (
    InsufficientFunds,
    TransactionAlreadyProcessed,
    WalletFrozen,
)
from dj_wallet.models import Transaction
from dj_wallet.services import WalletService


@pytest.mark.django_db
class TestTransactionStatus:
    """Tests for transaction status field."""

    def test_confirmed_transaction_has_completed_status(self, wallet):
        """Test that confirmed transactions have COMPLETED status."""
        txn = WalletService.deposit(wallet, Decimal("100.00"), confirmed=True)

        assert txn.status == Transaction.STATUS_COMPLETED
        assert txn.confirmed is True
        assert txn.is_completed

    def test_unconfirmed_transaction_has_pending_status(self, wallet):
        """Test that unconfirmed transactions have PENDING status."""
        txn = WalletService.deposit(wallet, Decimal("100.00"), confirmed=False)

        assert txn.status == Transaction.STATUS_PENDING
        assert txn.confirmed is False
        assert txn.is_pending

        # Balance should not be affected
        wallet.refresh_from_db()
        assert wallet.balance == Decimal("0")

    def test_pending_transaction_string_shows_status(self, wallet):
        """Test that pending transactions show status in string representation."""
        txn = WalletService.deposit(wallet, Decimal("100.00"), confirmed=False)

        assert "[PENDING]" in str(txn)

    def test_completed_transaction_string_no_status_indicator(self, wallet):
        """Test that completed transactions don't show extra status indicator."""
        txn = WalletService.deposit(wallet, Decimal("100.00"), confirmed=True)

        assert "[" not in str(txn)  # No status brackets

    def test_is_reversible_property(self, funded_wallet):
        """Test the is_reversible property."""
        # Completed transaction is reversible
        txn = funded_wallet.transactions.first()
        assert txn.is_reversible

        # Pending transaction is not reversible
        pending_txn = WalletService.deposit(
            funded_wallet, Decimal("50.00"), confirmed=False
        )
        assert not pending_txn.is_reversible


@pytest.mark.django_db
class TestConfirmTransaction:
    """Tests for confirming pending transactions."""

    def test_confirm_pending_deposit(self, wallet):
        """Test confirming a pending deposit transaction."""
        txn = WalletService.deposit(wallet, Decimal("100.00"), confirmed=False)

        wallet.refresh_from_db()
        assert wallet.balance == Decimal("0")

        confirmed_txn = WalletService.confirm_transaction(txn)

        wallet.refresh_from_db()
        assert wallet.balance == Decimal("100.00")
        assert confirmed_txn.status == Transaction.STATUS_COMPLETED
        assert confirmed_txn.confirmed is True

    def test_confirm_pending_withdrawal(self, funded_wallet):
        """Test confirming a pending withdrawal transaction."""
        initial_balance = funded_wallet.balance

        txn = WalletService.withdraw(funded_wallet, Decimal("50.00"), confirmed=False)

        funded_wallet.refresh_from_db()
        assert funded_wallet.balance == initial_balance  # Unchanged

        confirmed_txn = WalletService.confirm_transaction(txn)

        funded_wallet.refresh_from_db()
        assert funded_wallet.balance == initial_balance - Decimal("50.00")
        assert confirmed_txn.status == Transaction.STATUS_COMPLETED

    def test_confirm_already_completed_raises(self, funded_wallet):
        """Test that confirming a completed transaction raises error."""
        txn = funded_wallet.transactions.first()

        with pytest.raises(TransactionAlreadyProcessed) as exc_info:
            WalletService.confirm_transaction(txn)

        assert "already" in str(exc_info.value).lower()

    def test_confirm_withdrawal_insufficient_funds_raises(self, wallet):
        """Test confirming a withdrawal when balance is insufficient."""
        # Create pending withdrawal for more than current balance
        WalletService.deposit(wallet, Decimal("50.00"))
        txn = WalletService.withdraw(wallet, Decimal("100.00"), confirmed=False)

        with pytest.raises(InsufficientFunds):
            WalletService.confirm_transaction(txn)

    def test_confirm_on_frozen_wallet_raises(self, wallet):
        """Test that confirming on a frozen wallet raises WalletFrozen."""
        txn = WalletService.deposit(wallet, Decimal("100.00"), confirmed=False)

        wallet.freeze(reason="Account suspended")
        wallet.refresh_from_db()

        with pytest.raises(WalletFrozen):
            WalletService.confirm_transaction(txn)


@pytest.mark.django_db
class TestRejectTransaction:
    """Tests for rejecting pending transactions."""

    def test_reject_pending_transaction(self, wallet):
        """Test rejecting a pending transaction."""
        txn = WalletService.deposit(wallet, Decimal("100.00"), confirmed=False)

        rejected_txn = WalletService.reject_transaction(txn, reason="User cancelled")

        assert rejected_txn.status == Transaction.STATUS_FAILED
        assert rejected_txn.meta.get("rejection_reason") == "User cancelled"

        wallet.refresh_from_db()
        assert wallet.balance == Decimal("0")

    def test_reject_completed_transaction_raises(self, funded_wallet):
        """Test that rejecting a completed transaction raises error."""
        txn = funded_wallet.transactions.first()

        with pytest.raises(TransactionAlreadyProcessed):
            WalletService.reject_transaction(txn)


@pytest.mark.django_db
class TestReverseTransaction:
    """Tests for reversing completed transactions."""

    def test_reverse_deposit_transaction(self, funded_wallet):
        """Test reversing a deposit transaction."""
        original_txn = funded_wallet.transactions.first()

        reversal_txn = WalletService.reverse_transaction(
            original_txn, reason="Chargeback"
        )

        # Original should be marked as reversed
        original_txn.refresh_from_db()
        assert original_txn.status == Transaction.STATUS_REVERSED

        # Reversal should be a withdrawal
        assert reversal_txn.type == Transaction.TYPE_WITHDRAW
        assert reversal_txn.status == Transaction.STATUS_COMPLETED
        assert reversal_txn.meta.get("reversal_of") == str(original_txn.uuid)

        # Balance should be back to zero
        funded_wallet.refresh_from_db()
        assert funded_wallet.balance == Decimal("0")

    def test_reverse_withdrawal_transaction(self, user):
        """Test reversing a withdrawal transaction."""
        wallet = user.wallet
        WalletService.deposit(wallet, Decimal("100.00"))
        withdraw_txn = WalletService.withdraw(wallet, Decimal("50.00"))

        wallet.refresh_from_db()
        assert wallet.balance == Decimal("50.00")

        reversal_txn = WalletService.reverse_transaction(withdraw_txn, reason="Refund")

        # Reversal should be a deposit
        assert reversal_txn.type == Transaction.TYPE_DEPOSIT

        # Balance should be restored
        wallet.refresh_from_db()
        assert wallet.balance == Decimal("100.00")

    def test_reverse_pending_transaction_raises(self, wallet):
        """Test that reversing a pending transaction raises error."""
        txn = WalletService.deposit(wallet, Decimal("100.00"), confirmed=False)

        with pytest.raises(TransactionAlreadyProcessed) as exc_info:
            WalletService.reverse_transaction(txn)

        assert "completed" in str(exc_info.value).lower()

    def test_reverse_already_reversed_raises(self, funded_wallet):
        """Test that reversing an already reversed transaction raises error."""
        txn = funded_wallet.transactions.first()
        WalletService.reverse_transaction(txn)

        txn.refresh_from_db()

        with pytest.raises(TransactionAlreadyProcessed):
            WalletService.reverse_transaction(txn)

    def test_reverse_deposit_insufficient_funds_raises(self, funded_wallet):
        """Test reversing a deposit when balance is insufficient."""
        # Withdraw most of the balance first
        WalletService.withdraw(funded_wallet, Decimal("90.00"))

        # Try to reverse the original deposit
        deposit_txn = funded_wallet.transactions.filter(
            type=Transaction.TYPE_DEPOSIT
        ).first()

        with pytest.raises(InsufficientFunds):
            WalletService.reverse_transaction(deposit_txn)


@pytest.mark.django_db
class TestExpirePendingTransactions:
    """Tests for expiring pending transactions."""

    def test_expire_pending_transactions(self, wallet):
        """Test expiring old pending transactions."""
        from datetime import timedelta

        from django.utils import timezone

        # Create pending transactions
        txn1 = WalletService.deposit(wallet, Decimal("100.00"), confirmed=False)
        txn2 = WalletService.deposit(wallet, Decimal("50.00"), confirmed=False)

        # Expire all pending transactions before now (should expire both)
        count = WalletService.expire_pending_transactions(
            wallet, before_date=timezone.now() + timedelta(seconds=1)
        )

        assert count == 2

        txn1.refresh_from_db()
        txn2.refresh_from_db()

        assert txn1.status == Transaction.STATUS_EXPIRED
        assert txn2.status == Transaction.STATUS_EXPIRED

    def test_expire_does_not_affect_completed(self, funded_wallet):
        """Test that expiration does not affect completed transactions."""
        from datetime import timedelta

        from django.utils import timezone

        count = WalletService.expire_pending_transactions(
            funded_wallet, before_date=timezone.now() + timedelta(days=1)
        )

        assert count == 0

        # Completed transaction should remain
        txn = funded_wallet.transactions.first()
        assert txn.status == Transaction.STATUS_COMPLETED


@pytest.mark.django_db
class TestGetPendingTransactions:
    """Tests for getting pending transactions via mixin."""

    def test_get_pending_transactions(self, user):
        """Test retrieving pending transactions via mixin."""
        wallet = user.wallet

        WalletService.deposit(wallet, Decimal("100.00"), confirmed=True)
        WalletService.deposit(wallet, Decimal("50.00"), confirmed=False)
        WalletService.deposit(wallet, Decimal("25.00"), confirmed=False)

        pending = user.get_pending_transactions()

        assert pending.count() == 2
        for txn in pending:
            assert txn.status == Transaction.STATUS_PENDING
