from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("wallets_demo", "0027_operationsetting_nav_visibility_rules_and_more"),
    ]

    operations = [
        migrations.CreateModel(
            name="ServiceClassPolicy",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "entity_type",
                    models.CharField(
                        choices=[("customer", "Customer"), ("merchant", "Merchant")],
                        max_length=16,
                    ),
                ),
                ("code", models.CharField(max_length=8)),
                ("name", models.CharField(max_length=64)),
                ("description", models.CharField(blank=True, default="", max_length=255)),
                ("is_active", models.BooleanField(default=True)),
                ("allow_deposit", models.BooleanField(default=True)),
                ("allow_withdraw", models.BooleanField(default=True)),
                ("allow_transfer", models.BooleanField(default=True)),
                ("allow_fx", models.BooleanField(default=True)),
                ("allow_b2b", models.BooleanField(default=True)),
                ("allow_b2c", models.BooleanField(default=True)),
                ("allow_c2b", models.BooleanField(default=True)),
                ("allow_p2g", models.BooleanField(default=True)),
                ("allow_g2p", models.BooleanField(default=True)),
                (
                    "single_txn_limit",
                    models.DecimalField(blank=True, decimal_places=2, max_digits=20, null=True),
                ),
                ("daily_txn_count_limit", models.PositiveIntegerField(blank=True, null=True)),
                (
                    "daily_amount_limit",
                    models.DecimalField(blank=True, decimal_places=2, max_digits=20, null=True),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "ordering": ("entity_type", "code"),
                "constraints": [
                    models.UniqueConstraint(
                        fields=("entity_type", "code"),
                        name="uniq_service_class_policy_entity_code",
                    )
                ],
            },
        ),
        migrations.AddField(
            model_name="customercif",
            name="service_class",
            field=models.ForeignKey(
                blank=True,
                limit_choices_to={"entity_type": "customer"},
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="customer_cifs",
                to="wallets_demo.serviceclasspolicy",
            ),
        ),
        migrations.AddField(
            model_name="merchant",
            name="service_class",
            field=models.ForeignKey(
                blank=True,
                limit_choices_to={"entity_type": "merchant"},
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="merchants",
                to="wallets_demo.serviceclasspolicy",
            ),
        ),
    ]
