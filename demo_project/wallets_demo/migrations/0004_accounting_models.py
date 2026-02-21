from decimal import Decimal

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("wallets_demo", "0003_treasury_models"),
    ]

    operations = [
        migrations.CreateModel(
            name="ChartOfAccount",
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
                ("code", models.CharField(max_length=24, unique=True)),
                ("name", models.CharField(max_length=128)),
                (
                    "account_type",
                    models.CharField(
                        choices=[
                            ("asset", "Asset"),
                            ("liability", "Liability"),
                            ("equity", "Equity"),
                            ("revenue", "Revenue"),
                            ("expense", "Expense"),
                        ],
                        max_length=16,
                    ),
                ),
                ("currency", models.CharField(default="USD", max_length=12)),
                ("is_active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={"ordering": ("code",)},
        ),
        migrations.CreateModel(
            name="JournalEntry",
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
                ("entry_no", models.CharField(max_length=40, unique=True)),
                ("reference", models.CharField(blank=True, default="", max_length=128)),
                ("description", models.CharField(blank=True, default="", max_length=255)),
                (
                    "status",
                    models.CharField(
                        choices=[("draft", "Draft"), ("posted", "Posted")],
                        default="draft",
                        max_length=16,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("posted_at", models.DateTimeField(blank=True, null=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="created_journal_entries",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "posted_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="posted_journal_entries",
                        to="wallets_demo.user",
                    ),
                ),
            ],
            options={"ordering": ("-created_at",)},
        ),
        migrations.CreateModel(
            name="JournalLine",
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
                (
                    "debit",
                    models.DecimalField(
                        decimal_places=2, default=Decimal("0"), max_digits=20
                    ),
                ),
                (
                    "credit",
                    models.DecimalField(
                        decimal_places=2, default=Decimal("0"), max_digits=20
                    ),
                ),
                ("memo", models.CharField(blank=True, default="", max_length=255)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "account",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="journal_lines",
                        to="wallets_demo.chartofaccount",
                    ),
                ),
                (
                    "entry",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="lines",
                        to="wallets_demo.journalentry",
                    ),
                ),
            ],
            options={"ordering": ("id",)},
        ),
    ]
