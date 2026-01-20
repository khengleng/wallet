from django.db import models

from .abstract_models import AbstractTransaction, AbstractTransfer, AbstractWallet
from .conf import wallet_settings


class Wallet(AbstractWallet):
    """
    Concrete Wallet model.
    For custom wallet models, extend AbstractWallet instead.
    """

    class Meta(AbstractWallet.Meta):
        abstract = False
        db_table = f"{wallet_settings.WALLET_TABLE_PREFIX}wallet"
        indexes = [
            models.Index(fields=["holder_type", "holder_id", "slug"]),
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

    class Meta:
        abstract = False
        indexes = [
            models.Index(fields=["payable_type", "payable_id"]),
            models.Index(fields=["type"]),
            models.Index(fields=["confirmed"]),
            models.Index(fields=["wallet", "type"]),
        ]
        db_table = f"{wallet_settings.WALLET_TABLE_PREFIX}transaction"


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

    class Meta:
        abstract = False
        db_table = f"{wallet_settings.WALLET_TABLE_PREFIX}transfer"
        indexes = [
            models.Index(fields=["from_type", "from_id"]),
            models.Index(fields=["to_type", "to_id"]),
            models.Index(fields=["status"]),
        ]
