from django.contrib.auth.models import AbstractUser
from dj_wallet.mixins import WalletMixin

class User(WalletMixin, AbstractUser):
    pass
