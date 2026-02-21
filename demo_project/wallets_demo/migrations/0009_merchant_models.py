from decimal import Decimal

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("wallets_demo", "0008_fx_rate_source_fields"),
    ]

    operations = [
        migrations.CreateModel(
            name="Merchant",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("code", models.CharField(max_length=40, unique=True)),
                ("name", models.CharField(max_length=128)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("active", "Active"),
                            ("suspended", "Suspended"),
                            ("inactive", "Inactive"),
                        ],
                        default="active",
                        max_length=16,
                    ),
                ),
                ("settlement_currency", models.CharField(default="USD", max_length=12)),
                ("contact_email", models.EmailField(blank=True, default="", max_length=254)),
                ("contact_phone", models.CharField(blank=True, default="", max_length=40)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="created_merchants",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "owner",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="managed_merchants",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "updated_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="updated_merchants",
                        to="wallets_demo.user",
                    ),
                ),
            ],
            options={"ordering": ("code",)},
        ),
        migrations.CreateModel(
            name="MerchantLoyaltyEvent",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "event_type",
                    models.CharField(
                        choices=[("accrual", "Accrual"), ("redemption", "Redemption")],
                        max_length=16,
                    ),
                ),
                ("points", models.DecimalField(decimal_places=2, max_digits=20)),
                (
                    "amount",
                    models.DecimalField(
                        decimal_places=2,
                        default=Decimal("0"),
                        help_text="Settlement currency amount tied to the event.",
                        max_digits=20,
                    ),
                ),
                ("currency", models.CharField(default="USD", max_length=12)),
                ("reference", models.CharField(blank=True, default="", max_length=128)),
                ("note", models.CharField(blank=True, default="", max_length=255)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="created_loyalty_events",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "customer",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="loyalty_events",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "merchant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="loyalty_events",
                        to="wallets_demo.merchant",
                    ),
                ),
            ],
            options={"ordering": ("-created_at", "-id")},
        ),
        migrations.CreateModel(
            name="MerchantLoyaltyProgram",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("is_enabled", models.BooleanField(default=True)),
                (
                    "earn_rate",
                    models.DecimalField(
                        decimal_places=4,
                        default=Decimal("1.0000"),
                        help_text="Points earned for each 1 unit of settlement currency spent.",
                        max_digits=12,
                    ),
                ),
                (
                    "redeem_rate",
                    models.DecimalField(
                        decimal_places=4,
                        default=Decimal("1.0000"),
                        help_text="Currency value deducted for each 1 point redeemed.",
                        max_digits=12,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "merchant",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="loyalty_program",
                        to="wallets_demo.merchant",
                    ),
                ),
            ],
            options={"ordering": ("merchant__code",)},
        ),
    ]
