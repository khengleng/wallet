# django_bavix_wallet/services/common.py
from decimal import Decimal, InvalidOperation

from django.db import transaction

from ..exceptions import AmountInvalid, InsufficientFunds
from ..models import Transaction, Wallet
from ..signals import balance_changed, transaction_created


class WalletService:
    @staticmethod
    def verify_amount(amount):
        """
        Ensures amount is valid decimal and positive.
        Replaces internal PHP validation logic.
        """
        try:
            val = Decimal(
                str(amount)
            )  # Convert to string first to avoid float precision issues
        except (ValueError, InvalidOperation):
            raise AmountInvalid("Amount must be a number.") from None

        if val <= 0:
            raise AmountInvalid("Amount must be positive.")
        return val

    @classmethod
    def deposit(cls, wallet, amount, meta=None, confirmed=True):
        """
        Performs a deposit. Wraps logic in atomic block with row locking.
        """
        amount = cls.verify_amount(amount)
        meta = meta or {}

        with transaction.atomic():
            # Lock the wallet row to prevent concurrent modifications
            # We must reload the wallet object to ensure we have the locked version
            locked_wallet = Wallet.objects.select_for_update().get(pk=wallet.pk)

            # Create the immutable transaction record
            txn = Transaction.objects.create(
                payable=locked_wallet,
                wallet=locked_wallet,
                type=Transaction.TYPE_DEPOSIT,
                amount=amount,
                confirmed=confirmed,
                meta=meta,
            )

            if confirmed:
                locked_wallet.balance += amount
                locked_wallet.save()

                # Signal dispatching
                balance_changed.send(sender=cls, wallet=locked_wallet, transaction=txn)

            transaction_created.send(sender=cls, transaction=txn)

            return txn

    @classmethod
    def withdraw(cls, wallet, amount, meta=None, confirmed=True):
        """
        Performs a withdrawal. Checks for sufficient funds inside the lock.
        """
        amount = cls.verify_amount(amount)
        meta = meta or {}

        with transaction.atomic():
            locked_wallet = Wallet.objects.select_for_update().get(pk=wallet.pk)

            # Check balance *after* acquiring lock
            if confirmed and locked_wallet.balance < amount:
                raise InsufficientFunds(
                    f"Insufficient funds. Balance: {locked_wallet.balance}, Required: {amount}"
                )

            txn = Transaction.objects.create(
                payable=locked_wallet,
                wallet=locked_wallet,
                type=Transaction.TYPE_WITHDRAW,
                amount=amount,
                confirmed=confirmed,
                meta=meta,
            )

            if confirmed:
                locked_wallet.balance -= amount
                locked_wallet.save()
                balance_changed.send(sender=cls, wallet=locked_wallet, transaction=txn)

            transaction_created.send(sender=cls, transaction=txn)

            return txn

    @classmethod
    def force_withdraw(cls, wallet, amount, meta=None, confirmed=True):
        """
        Withdraws even if balance is insufficient (can go negative).
        """
        amount = cls.verify_amount(amount)
        meta = meta or {}

        with transaction.atomic():
            locked_wallet = Wallet.objects.select_for_update().get(pk=wallet.pk)

            txn = Transaction.objects.create(
                payable=locked_wallet,
                wallet=locked_wallet,
                type=Transaction.TYPE_WITHDRAW,
                amount=amount,
                confirmed=confirmed,
                meta=meta,
            )

            if confirmed:
                locked_wallet.balance -= amount
                locked_wallet.save()
                balance_changed.send(sender=cls, wallet=locked_wallet, transaction=txn)

            transaction_created.send(sender=cls, transaction=txn)

            return txn
