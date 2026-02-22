from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("wallets_demo", "0028_service_class_policy"),
    ]

    operations = [
        migrations.CreateModel(
            name="TariffRule",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("transaction_type", models.CharField(db_index=True, max_length=32)),
                ("name", models.CharField(max_length=96)),
                ("description", models.CharField(blank=True, default="", max_length=255)),
                ("is_active", models.BooleanField(db_index=True, default=True)),
                (
                    "priority",
                    models.PositiveIntegerField(default=100, help_text="Lower value = higher priority."),
                ),
                (
                    "payer_entity_type",
                    models.CharField(
                        choices=[("any", "Any"), ("customer", "Customer"), ("merchant", "Merchant")],
                        default="any",
                        max_length=16,
                    ),
                ),
                (
                    "payee_entity_type",
                    models.CharField(
                        choices=[("any", "Any"), ("customer", "Customer"), ("merchant", "Merchant")],
                        default="any",
                        max_length=16,
                    ),
                ),
                (
                    "currency",
                    models.CharField(
                        blank=True,
                        default="",
                        help_text="Leave empty to apply to any currency.",
                        max_length=12,
                    ),
                ),
                ("min_amount", models.DecimalField(blank=True, decimal_places=2, max_digits=20, null=True)),
                ("max_amount", models.DecimalField(blank=True, decimal_places=2, max_digits=20, null=True)),
                (
                    "charge_side",
                    models.CharField(
                        choices=[("payer", "Charge Payer"), ("payee", "Charge Payee")],
                        default="payer",
                        max_length=8,
                    ),
                ),
                (
                    "fee_mode",
                    models.CharField(
                        choices=[("flat", "Flat Amount"), ("bps", "Percent (BPS)")],
                        default="flat",
                        max_length=8,
                    ),
                ),
                ("fee_value", models.DecimalField(decimal_places=6, default=0, max_digits=20)),
                ("minimum_fee", models.DecimalField(blank=True, decimal_places=2, max_digits=20, null=True)),
                ("maximum_fee", models.DecimalField(blank=True, decimal_places=2, max_digits=20, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "payee_service_class",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="payee_tariff_rules",
                        to="wallets_demo.serviceclasspolicy",
                    ),
                ),
                (
                    "payer_service_class",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="payer_tariff_rules",
                        to="wallets_demo.serviceclasspolicy",
                    ),
                ),
            ],
            options={"ordering": ("priority", "id")},
        ),
    ]
