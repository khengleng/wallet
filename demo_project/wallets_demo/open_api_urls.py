from django.urls import path

from . import views_open_api

app_name = "open_api"

urlpatterns = [
    path("docs/", views_open_api.open_api_docs, name="docs"),
    path("merchant/wallet/balance/", views_open_api.open_api_merchant_wallet_balance, name="merchant_wallet_balance"),
    path("payments/c2b/", views_open_api.open_api_payment_c2b, name="payment_c2b"),
    path("payouts/b2c/", views_open_api.open_api_payout_b2c, name="payout_b2c"),
    path("sandbox/payments/c2b/", views_open_api.open_api_sandbox_payment_c2b, name="sandbox_payment_c2b"),
    path("sandbox/payouts/b2c/", views_open_api.open_api_sandbox_payout_b2c, name="sandbox_payout_b2c"),
]
