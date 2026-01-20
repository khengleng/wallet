# django_wallets/abstract_models.py
"""
Abstract base models for django-wallets.

These abstract models contain all the fields and logic for wallets, transactions, and transfers.
Developers can extend these to create custom models with additional fields or modified behavior.

Usage:
    from django_wallets.abstract_models import AbstractWallet

    class CustomWallet(AbstractWallet):
        custom_field = models.CharField(max_length=100)

        class Meta(AbstractWallet.Meta):
            abstract = False
"""
import uuid
from decimal import Decimal

from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.utils.translation import gettext_lazy as _

from .conf import wallet_settings
from .managers import TransactionManager, WalletManager


class AbstractWallet(models.Model):
    """
    Abstract base class for Wallet model.
    Extend this class to create a custom wallet model with additional fields.
    Remember to set ``abstract = False`` in your Meta class and update
    ``DJANGO_WALLETS['WALLET_MODEL']`` setting.
    """

    # The owner of the wallet (User, Organization, etc.)
    holder_type = models.ForeignKey(
        ContentType, on_delete=models.CASCADE, related_name="%(class)s_wallets"
    )
    holder_id = models.PositiveIntegerField()
    holder = GenericForeignKey("holder_type", "holder_id")

    # Slug allows multiple wallets per user (e.g., 'default', 'savings', 'usd')
    slug = models.SlugField(default="default", help_text=_("The name of the wallet"))

    # Unique identifier for API usage
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)

    # The cached balance
    balance = models.DecimalField(
        max_digits=64,
        decimal_places=wallet_settings.WALLET_MATH_SCALE,
        default=Decimal("0.00"),
    )

    # Configuration for this specific wallet
    decimal_places = models.PositiveSmallIntegerField(
        default=wallet_settings.WALLET_MATH_SCALE
    )

    # Metadata for the wallet
    meta = models.JSONField(blank=True, null=True, default=dict)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = WalletManager()

    class Meta:
        abstract = True
        unique_together = (("holder_type", "holder_id", "slug"),)
        verbose_name = _("Wallet")
        verbose_name_plural = _("Wallets")

    def __str__(self):
        return f"{self.slug} ({self.balance})"

    @property
    def currency(self):
        return self.meta.get("currency", wallet_settings.WALLET_DEFAULT_CURRENCY)


class AbstractTransaction(models.Model):
    """
    Abstract base class for Transaction model.
    Extend this class to create a custom transaction model with additional fields.
    """

    TYPE_DEPOSIT = "deposit"
    TYPE_WITHDRAW = "withdraw"

    TYPE_CHOICES = (
        (TYPE_DEPOSIT, _("Deposit")),
        (TYPE_WITHDRAW, _("Withdraw")),
    )

    # The entity causing the transaction
    payable_type = models.ForeignKey(
        ContentType, on_delete=models.CASCADE, related_name="%(class)s_transactions"
    )
    payable_id = models.PositiveIntegerField()
    payable = GenericForeignKey("payable_type", "payable_id")

    # Note: wallet FK is defined in concrete class to allow custom wallet model

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    amount = models.DecimalField(
        max_digits=64, decimal_places=wallet_settings.WALLET_MATH_SCALE
    )
    confirmed = models.BooleanField(default=True)

    meta = models.JSONField(blank=True, null=True, default=dict)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = TransactionManager()

    class Meta:
        abstract = True

    def __str__(self):
        return f"{self.type} {self.amount}"


class AbstractTransfer(models.Model):
    """
    Abstract base class for Transfer model.
    Extend this class to create a custom transfer model with additional fields.
    """

    STATUS_EXCHANGE = "exchange"
    STATUS_TRANSFER = "transfer"
    STATUS_PAID = "paid"
    STATUS_REFUND = "refund"
    STATUS_GIFT = "gift"

    STATUS_CHOICES = (
        (STATUS_EXCHANGE, _("Exchange")),
        (STATUS_TRANSFER, _("Transfer")),
        (STATUS_PAID, _("Paid")),
        (STATUS_REFUND, _("Refund")),
        (STATUS_GIFT, _("Gift")),
    )

    # Sender (Polymorphic)
    from_type = models.ForeignKey(
        ContentType, on_delete=models.CASCADE, related_name="%(class)s_transfers_sent"
    )
    from_id = models.PositiveIntegerField()
    from_object = GenericForeignKey("from_type", "from_id")

    # Receiver
    to_type = models.ForeignKey(
        ContentType, on_delete=models.CASCADE, related_name="%(class)s_transfers_received"
    )
    to_id = models.PositiveIntegerField()
    to_object = GenericForeignKey("to_type", "to_id")

    # Note: withdraw/deposit FKs defined in concrete class to allow custom transaction model

    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default=STATUS_TRANSFER
    )

    discount = models.DecimalField(
        max_digits=64, decimal_places=wallet_settings.WALLET_MATH_SCALE, default=0
    )
    fee = models.DecimalField(
        max_digits=64, decimal_places=wallet_settings.WALLET_MATH_SCALE, default=0
    )

    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

    def __str__(self):
        return f"Transfer {self.status} ({self.uuid})"
