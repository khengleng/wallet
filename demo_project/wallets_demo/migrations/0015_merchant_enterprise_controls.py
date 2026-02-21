from decimal import Decimal

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("wallets_demo", "0014_customercif"),
    ]

    operations = [
        migrations.AddField(
            model_name="merchantcashflowevent",
            name="fee_amount",
            field=models.DecimalField(decimal_places=2, default=Decimal("0"), max_digits=20),
        ),
        migrations.AddField(
            model_name="merchantcashflowevent",
            name="net_amount",
            field=models.DecimalField(decimal_places=2, default=Decimal("0"), max_digits=20),
        ),
        migrations.AddField(
            model_name="merchantcashflowevent",
            name="settled_at",
            field=models.DateTimeField(blank=True, db_index=True, null=True),
        ),
        migrations.AddField(
            model_name="merchantcashflowevent",
            name="settlement_reference",
            field=models.CharField(blank=True, db_index=True, default="", max_length=48),
        ),
        migrations.CreateModel(
            name="MerchantApiCredential",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("key_id", models.CharField(max_length=64, unique=True)),
                ("secret_hash", models.CharField(max_length=128)),
                ("webhook_url", models.URLField(blank=True, default="")),
                ("is_active", models.BooleanField(default=True)),
                ("last_rotated_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="created_merchant_api_credentials",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "merchant",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="api_credential",
                        to="wallets_demo.merchant",
                    ),
                ),
                (
                    "updated_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="updated_merchant_api_credentials",
                        to="wallets_demo.user",
                    ),
                ),
            ],
            options={"ordering": ("merchant__code",)},
        ),
        migrations.CreateModel(
            name="MerchantKYBRequest",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "status",
                    models.CharField(
                        choices=[("pending", "Pending"), ("approved", "Approved"), ("rejected", "Rejected")],
                        db_index=True,
                        default="pending",
                        max_length=16,
                    ),
                ),
                ("legal_name", models.CharField(max_length=128)),
                ("registration_number", models.CharField(blank=True, default="", max_length=64)),
                ("tax_id", models.CharField(blank=True, default="", max_length=64)),
                ("country_code", models.CharField(blank=True, default="", max_length=3)),
                ("documents_json", models.JSONField(blank=True, default=dict)),
                ("risk_note", models.CharField(blank=True, default="", max_length=255)),
                ("checker_note", models.CharField(blank=True, default="", max_length=255)),
                ("decided_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "checker",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="checked_kyb_requests",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "maker",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="created_kyb_requests",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "merchant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="kyb_requests",
                        to="wallets_demo.merchant",
                    ),
                ),
            ],
            options={"ordering": ("-created_at", "-id")},
        ),
        migrations.CreateModel(
            name="MerchantRiskProfile",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("daily_txn_limit", models.PositiveIntegerField(default=5000)),
                ("daily_amount_limit", models.DecimalField(decimal_places=2, default=Decimal("1000000"), max_digits=20)),
                ("single_txn_limit", models.DecimalField(decimal_places=2, default=Decimal("50000"), max_digits=20)),
                ("reserve_ratio_bps", models.PositiveIntegerField(default=0)),
                ("require_manual_review_above", models.DecimalField(decimal_places=2, default=Decimal("0"), max_digits=20)),
                ("is_high_risk", models.BooleanField(default=False)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "merchant",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="risk_profile",
                        to="wallets_demo.merchant",
                    ),
                ),
                (
                    "updated_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="updated_merchant_risk_profiles",
                        to="wallets_demo.user",
                    ),
                ),
            ],
            options={"ordering": ("merchant__code",)},
        ),
        migrations.CreateModel(
            name="MerchantSettlementRecord",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("settlement_no", models.CharField(max_length=40, unique=True)),
                ("currency", models.CharField(default="USD", max_length=12)),
                ("period_start", models.DateField()),
                ("period_end", models.DateField()),
                ("gross_amount", models.DecimalField(decimal_places=2, default=Decimal("0"), max_digits=20)),
                ("fee_amount", models.DecimalField(decimal_places=2, default=Decimal("0"), max_digits=20)),
                ("net_amount", models.DecimalField(decimal_places=2, default=Decimal("0"), max_digits=20)),
                ("event_count", models.PositiveIntegerField(default=0)),
                (
                    "status",
                    models.CharField(
                        choices=[("draft", "Draft"), ("posted", "Posted"), ("paid", "Paid")],
                        db_index=True,
                        default="draft",
                        max_length=12,
                    ),
                ),
                ("approved_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "approved_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="approved_merchant_settlements",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "created_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="created_merchant_settlements",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "merchant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="settlement_records",
                        to="wallets_demo.merchant",
                    ),
                ),
            ],
            options={"ordering": ("-created_at", "-id")},
        ),
        migrations.CreateModel(
            name="MerchantFeeRule",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("flow_type", models.CharField(choices=[("b2b", "B2B"), ("b2c", "B2C"), ("c2b", "C2B"), ("p2g", "P2G"), ("g2p", "G2P")], max_length=8)),
                ("percent_bps", models.PositiveIntegerField(default=0, help_text="Fee percentage in basis points.")),
                ("fixed_fee", models.DecimalField(decimal_places=2, default=Decimal("0"), max_digits=20)),
                ("minimum_fee", models.DecimalField(decimal_places=2, default=Decimal("0"), max_digits=20)),
                ("maximum_fee", models.DecimalField(decimal_places=2, default=Decimal("0"), max_digits=20)),
                ("is_active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="created_merchant_fee_rules",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "merchant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="fee_rules",
                        to="wallets_demo.merchant",
                    ),
                ),
                (
                    "updated_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="updated_merchant_fee_rules",
                        to="wallets_demo.user",
                    ),
                ),
            ],
            options={"ordering": ("merchant__code", "flow_type"), "unique_together": {("merchant", "flow_type")}},
        ),
    ]
