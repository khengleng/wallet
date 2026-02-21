from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("wallets_demo", "0009_merchant_models"),
    ]

    operations = [
        migrations.CreateModel(
            name="MerchantWalletCapability",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("supports_b2b", models.BooleanField(default=True)),
                ("supports_b2c", models.BooleanField(default=True)),
                ("supports_c2b", models.BooleanField(default=True)),
                ("supports_p2g", models.BooleanField(default=False)),
                ("supports_g2p", models.BooleanField(default=False)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "merchant",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="wallet_capability",
                        to="wallets_demo.merchant",
                    ),
                ),
            ],
            options={
                "verbose_name_plural": "Merchant wallet capabilities",
                "ordering": ("merchant__code",),
            },
        ),
        migrations.AddField(
            model_name="merchantloyaltyevent",
            name="flow_type",
            field=models.CharField(
                choices=[
                    ("b2b", "B2B"),
                    ("b2c", "B2C"),
                    ("c2b", "C2B"),
                    ("p2g", "P2G"),
                    ("g2p", "G2P"),
                ],
                default="b2c",
                max_length=8,
            ),
        ),
        migrations.CreateModel(
            name="OperationCase",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("case_no", models.CharField(max_length=40, unique=True)),
                (
                    "case_type",
                    models.CharField(
                        choices=[
                            ("complaint", "Complaint"),
                            ("dispute", "Dispute"),
                            ("refund", "Refund"),
                            ("incident", "Incident"),
                        ],
                        max_length=16,
                    ),
                ),
                (
                    "priority",
                    models.CharField(
                        choices=[
                            ("low", "Low"),
                            ("medium", "Medium"),
                            ("high", "High"),
                            ("critical", "Critical"),
                        ],
                        default="medium",
                        max_length=16,
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("open", "Open"),
                            ("in_progress", "In Progress"),
                            ("escalated", "Escalated"),
                            ("resolved", "Resolved"),
                            ("closed", "Closed"),
                        ],
                        db_index=True,
                        default="open",
                        max_length=16,
                    ),
                ),
                ("title", models.CharField(max_length=255)),
                ("description", models.TextField(blank=True, default="")),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("resolved_at", models.DateTimeField(blank=True, null=True)),
                (
                    "assigned_to",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="assigned_operation_cases",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "created_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="created_operation_cases",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "customer",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="operation_cases",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "merchant",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="operation_cases",
                        to="wallets_demo.merchant",
                    ),
                ),
            ],
            options={"ordering": ("-created_at",)},
        ),
        migrations.CreateModel(
            name="OperationCaseNote",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("note", models.TextField()),
                ("is_internal", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                (
                    "case",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="notes",
                        to="wallets_demo.operationcase",
                    ),
                ),
                (
                    "created_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="operation_case_notes",
                        to="wallets_demo.user",
                    ),
                ),
            ],
            options={"ordering": ("-created_at",)},
        ),
    ]
