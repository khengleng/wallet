from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("wallets_demo", "0010_business_operations_models"),
    ]

    operations = [
        migrations.AddField(
            model_name="merchant",
            name="is_government",
            field=models.BooleanField(default=False),
        ),
        migrations.CreateModel(
            name="MerchantCashflowEvent",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "flow_type",
                    models.CharField(
                        choices=[
                            ("b2b", "B2B"),
                            ("b2c", "B2C"),
                            ("c2b", "C2B"),
                            ("p2g", "P2G"),
                            ("g2p", "G2P"),
                        ],
                        max_length=8,
                    ),
                ),
                ("amount", models.DecimalField(decimal_places=2, max_digits=20)),
                ("currency", models.CharField(default="USD", max_length=12)),
                ("reference", models.CharField(blank=True, default="", max_length=128)),
                ("note", models.CharField(blank=True, default="", max_length=255)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                (
                    "counterparty_merchant",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="counterparty_cashflow_events",
                        to="wallets_demo.merchant",
                    ),
                ),
                (
                    "created_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="created_cashflow_events",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "from_user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="merchant_cashflow_outgoing",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "merchant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="cashflow_events",
                        to="wallets_demo.merchant",
                    ),
                ),
                (
                    "to_user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="merchant_cashflow_incoming",
                        to="wallets_demo.user",
                    ),
                ),
            ],
            options={"ordering": ("-created_at", "-id")},
        ),
    ]
