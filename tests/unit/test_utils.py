"""
Tests for utility resolvers.
"""

from dj_wallet.mixins import WalletMixin
from dj_wallet.models import Transaction, Transfer, Wallet
from dj_wallet.utils import (
    get_transaction_model,
    get_transfer_model,
    get_wallet_mixin,
    get_wallet_model,
)


def test_get_wallet_mixin_default():
    """Wallet mixin resolver should return configured default."""
    assert get_wallet_mixin() is WalletMixin


def test_get_wallet_model_default():
    """Wallet model resolver should return configured default."""
    assert get_wallet_model() is Wallet


def test_get_transaction_model_default():
    """Transaction model resolver should return configured default."""
    assert get_transaction_model() is Transaction


def test_get_transfer_model_default():
    """Transfer model resolver should return configured default."""
    assert get_transfer_model() is Transfer
