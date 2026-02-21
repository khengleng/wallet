from decimal import Decimal

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("wallets_demo", "0002_approvalrequest"),
    ]

    operations = [
        migrations.CreateModel(
            name="TreasuryAccount",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("name", models.CharField(max_length=64, unique=True)),
                ("currency", models.CharField(default="USD", max_length=12)),
                (
                    "balance",
                    models.DecimalField(
                        decimal_places=2, default=Decimal("0"), max_digits=20
                    ),
                ),
                ("is_active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ("name",)},
        ),
        migrations.CreateModel(
            name="TreasuryTransferRequest",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("amount", models.DecimalField(decimal_places=2, max_digits=20)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("approved", "Approved"),
                            ("rejected", "Rejected"),
                            ("failed", "Failed"),
                        ],
                        db_index=True,
                        default="pending",
                        max_length=16,
                    ),
                ),
                ("reason", models.CharField(blank=True, default="", max_length=255)),
                ("maker_note", models.TextField(blank=True, default="")),
                ("checker_note", models.TextField(blank=True, default="")),
                ("error_message", models.TextField(blank=True, default="")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("decided_at", models.DateTimeField(blank=True, null=True)),
                (
                    "checker",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="checked_treasury_requests",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "from_account",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="outgoing_requests",
                        to="wallets_demo.treasuryaccount",
                    ),
                ),
                (
                    "maker",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="made_treasury_requests",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "to_account",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="incoming_requests",
                        to="wallets_demo.treasuryaccount",
                    ),
                ),
            ],
            options={"ordering": ("-created_at",)},
        ),
    ]
