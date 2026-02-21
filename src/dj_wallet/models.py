from django.db import models

from .abstract_models import AbstractTransaction, AbstractTransfer, AbstractWallet


class Wallet(AbstractWallet):
    """
    Concrete Wallet model.
    For custom wallet models, extend AbstractWallet instead.
    """

    class Meta(AbstractWallet.Meta):
        indexes = [
            models.Index(fields=["holder_type", "holder_id"], name="wallet_holder_idx"),
        ]


class Transaction(AbstractTransaction):
    """
    Concrete Transaction model.
    For custom transaction models, extend AbstractTransaction instead.
    """

    # The specific wallet this transaction affects
    wallet = models.ForeignKey(
        Wallet, on_delete=models.CASCADE, related_name="transactions"
    )

    class Meta(AbstractTransaction.Meta):
        indexes = [
            models.Index(
                fields=["wallet", "status", "created_at"],
                name="txn_wallet_status_created_idx",
            ),
            models.Index(
                fields=["wallet", "type", "created_at"],
                name="txn_wallet_type_created_idx",
            ),
        ]


class Transfer(AbstractTransfer):
    """
    Concrete Transfer model.
    For custom transfer models, extend AbstractTransfer instead.
    """

    # The transaction withdrawing money from sender
    withdraw = models.ForeignKey(
        Transaction, on_delete=models.CASCADE, related_name="transfer_withdraw"
    )

    # The transaction depositing money to receiver
    deposit = models.ForeignKey(
        Transaction, on_delete=models.CASCADE, related_name="transfer_deposit"
    )

    class Meta(AbstractTransfer.Meta):
        indexes = [
            models.Index(fields=["status", "created_at"], name="transfer_status_created_idx"),
            models.Index(fields=["from_type", "from_id"], name="transfer_from_obj_idx"),
            models.Index(fields=["to_type", "to_id"], name="transfer_to_obj_idx"),
        ]
