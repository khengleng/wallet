from django.apps import apps
from django.utils.module_loading import import_string

from .conf import wallet_settings


def get_wallet_service():
    """
    Returns the configured WalletService class.
    Override via settings: dj_wallet['WALLET_SERVICE_CLASS']
    Example:
        WalletService = get_wallet_service()
        WalletService.deposit(wallet, amount)
    """
    return import_string(wallet_settings.WALLET_SERVICE_CLASS)


def get_transfer_service():
    """
    Returns the configured TransferService class.
    Override via settings: dj_wallet['TRANSFER_SERVICE_CLASS']
    """
    return import_string(wallet_settings.TRANSFER_SERVICE_CLASS)


def get_exchange_service():
    """
    Returns the configured ExchangeService class.
    Override via settings: dj_wallet['EXCHANGE_SERVICE_CLASS']
    """
    return import_string(wallet_settings.EXCHANGE_SERVICE_CLASS)


def get_purchase_service():
    """
    Returns the configured PurchaseService class.
    Override via settings: dj_wallet['PURCHASE_SERVICE_CLASS']
    """
    return import_string(wallet_settings.PURCHASE_SERVICE_CLASS)


def get_wallet_mixin():
    """
    Returns the configured WalletMixin class.
    Override via settings: dj_wallet['WALLET_MIXIN_CLASS']
    """
    return import_string(wallet_settings.WALLET_MIXIN_CLASS)


def get_wallet_model():
    """
    Returns the configured Wallet model class.
    Override via settings: dj_wallet['WALLET_MODEL']
    """
    return apps.get_model(wallet_settings.WALLET_MODEL)


def get_transaction_model():
    """
    Returns the configured Transaction model class.
    Override via settings: dj_wallet['TRANSACTION_MODEL']
    """
    return apps.get_model(wallet_settings.TRANSACTION_MODEL)


def get_transfer_model():
    """
    Returns the configured Transfer model class.
    Override via settings: dj_wallet['TRANSFER_MODEL']
    """
    return apps.get_model(wallet_settings.TRANSFER_MODEL)
