"""
Django app configuration for dj_wallet.
"""

from django.apps import AppConfig
from django.db.models.signals import post_save


def _emit_wallet_created(sender, instance, created, **kwargs):
    """Bridge Django post_save to dj_wallet.wallet_created signal."""
    if not created:
        return
    from .signals import wallet_created

    wallet_created.send(sender=sender, wallet=instance, holder=instance.holder)


class DjangoWalletsConfig(AppConfig):
    """Configuration for the Django Wallets application."""

    name = "dj_wallet"
    verbose_name = "Django Wallets"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        """Import signals when the app is ready."""
        # Import signals to register them
        from . import signals  # noqa: F401
        from .utils import get_wallet_model

        post_save.connect(
            _emit_wallet_created,
            sender=get_wallet_model(),
            dispatch_uid="dj_wallet.wallet_created.post_save",
        )
