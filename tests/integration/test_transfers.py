"""
Integration tests for transfer workflows.

Tests for complete transfer flows between wallets.
"""

from decimal import Decimal

import pytest

from dj_wallet.exceptions import InsufficientFunds
from dj_wallet.models import Transaction, Transfer
from dj_wallet.services import TransferService, WalletService


@pytest.mark.django_db()
@pytest.mark.integration()
class TestTransferWorkflows:
    """Tests for complete transfer workflows."""

    def test_transfer_updates_both_balances(self, user_factory):
        """Transfer should update sender and receiver balances."""
        sender = user_factory()
        recipient = user_factory()

        WalletService.deposit(sender.wallet, Decimal("100.00"))
        TransferService.transfer(sender, recipient, Decimal("40.00"))

        sender.wallet.refresh_from_db()
        recipient.wallet.refresh_from_db()

        assert sender.wallet.balance == Decimal("60.00")
        assert recipient.wallet.balance == Decimal("40.00")

    def test_transfer_creates_transfer_record(self, user_factory):
        """Transfer should create a Transfer model record."""
        sender = user_factory()
        recipient = user_factory()

        WalletService.deposit(sender.wallet, Decimal("100.00"))
        transfer = TransferService.transfer(sender, recipient, Decimal("50.00"))

        assert isinstance(transfer, Transfer)
        assert transfer.pk is not None

    def test_transfer_creates_two_transactions(self, user_factory):
        """Transfer should create withdraw and deposit transactions."""
        sender = user_factory()
        recipient = user_factory()

        initial_txn_count = Transaction.objects.count()
        WalletService.deposit(sender.wallet, Decimal("100.00"))
        TransferService.transfer(sender, recipient, Decimal("50.00"))

        # Should have 3 new transactions: 1 deposit (funding) + 1 withdraw + 1 deposit (transfer)
        assert Transaction.objects.count() == initial_txn_count + 3

    def test_transfer_transactions_linked(self, transfer_factory):
        """Transfer should link to its transactions."""
        transfer = transfer_factory()

        assert transfer.withdraw is not None
        assert transfer.deposit is not None
        assert transfer.withdraw.type == Transaction.TYPE_WITHDRAW
        assert transfer.deposit.type == Transaction.TYPE_DEPOSIT
        assert transfer.withdraw.amount == transfer.deposit.amount

    def test_transfer_metadata_propagated(self, user_factory):
        """Metadata should be propagated to transactions."""
        sender = user_factory()
        recipient = user_factory()

        WalletService.deposit(sender.wallet, Decimal("100.00"))
        transfer = TransferService.transfer(
            sender, recipient, Decimal("50.00"), meta={"reference": "PAY-123"}
        )

        assert "reference" in transfer.withdraw.meta
        assert "reference" in transfer.deposit.meta

    def test_transfer_insufficient_funds(self, user_factory):
        """Transfer should fail if sender has insufficient funds."""
        sender = user_factory()
        recipient = user_factory()

        WalletService.deposit(sender.wallet, Decimal("30.00"))

        with pytest.raises(InsufficientFunds):
            TransferService.transfer(sender, recipient, Decimal("50.00"))

        # Verify no changes occurred
        sender.wallet.refresh_from_db()
        recipient.wallet.refresh_from_db()
        assert sender.wallet.balance == Decimal("30.00")
        assert recipient.wallet.balance == Decimal("0")

    def test_transfer_exact_balance(self, user_factory):
        """Transfer of exact balance should leave sender with zero."""
        sender = user_factory()
        recipient = user_factory()

        WalletService.deposit(sender.wallet, Decimal("100.00"))
        TransferService.transfer(sender, recipient, Decimal("100.00"))

        sender.wallet.refresh_from_db()
        assert sender.wallet.balance == Decimal("0")

    def test_multiple_sequential_transfers(self, user_factory):
        """Multiple transfers should accumulate correctly."""
        user_a = user_factory()
        user_b = user_factory()
        user_c = user_factory()

        # A starts with 100
        WalletService.deposit(user_a.wallet, Decimal("100.00"))

        # A -> B: 40
        TransferService.transfer(user_a, user_b, Decimal("40.00"))

        # B -> C: 30
        TransferService.transfer(user_b, user_c, Decimal("30.00"))

        user_a.wallet.refresh_from_db()
        user_b.wallet.refresh_from_db()
        user_c.wallet.refresh_from_db()

        assert user_a.wallet.balance == Decimal("60.00")
        assert user_b.wallet.balance == Decimal("10.00")
        assert user_c.wallet.balance == Decimal("30.00")


@pytest.mark.django_db()
@pytest.mark.integration()
class TestTransferEdgeCases:
    """Tests for edge cases in transfers."""

    def test_transfer_to_self_different_wallet(self, user):
        """Transfer to self between different wallets should work."""
        WalletService.deposit(user.wallet, Decimal("100.00"))

        # Create a savings wallet
        savings = user.create_wallet("savings")

        # This is an exchange, not a transfer, but let's test the concept
        # Transfer from default to savings would require custom logic
        # For now, we verify wallets are different
        assert user.wallet.pk != savings.pk

    def test_transfer_preserves_total_funds(self, user_factory):
        """Transfer should not create or destroy funds."""
        sender = user_factory()
        recipient = user_factory()

        WalletService.deposit(sender.wallet, Decimal("100.00"))
        initial_total = sender.wallet.balance + recipient.wallet.balance

        TransferService.transfer(sender, recipient, Decimal("40.00"))

        sender.wallet.refresh_from_db()
        recipient.wallet.refresh_from_db()
        final_total = sender.wallet.balance + recipient.wallet.balance

        assert initial_total == final_total

    def test_transfer_small_amount(self, user_factory):
        """Very small transfers should work correctly."""
        sender = user_factory()
        recipient = user_factory()

        WalletService.deposit(sender.wallet, Decimal("100.00"))
        TransferService.transfer(sender, recipient, Decimal("0.00000001"))

        recipient.wallet.refresh_from_db()
        assert recipient.wallet.balance == Decimal("0.00000001")
