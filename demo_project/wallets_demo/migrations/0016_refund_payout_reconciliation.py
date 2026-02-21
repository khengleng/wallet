from decimal import Decimal

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("wallets_demo", "0015_merchant_enterprise_controls"),
    ]

    operations = [
        migrations.CreateModel(
            name="ReconciliationRun",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("source", models.CharField(default="internal_vs_settlement", max_length=64)),
                ("run_no", models.CharField(max_length=40, unique=True)),
                ("currency", models.CharField(default="USD", max_length=12)),
                ("period_start", models.DateField()),
                ("period_end", models.DateField()),
                ("internal_count", models.PositiveIntegerField(default=0)),
                ("internal_amount", models.DecimalField(decimal_places=2, default=Decimal("0"), max_digits=20)),
                ("external_count", models.PositiveIntegerField(default=0)),
                ("external_amount", models.DecimalField(decimal_places=2, default=Decimal("0"), max_digits=20)),
                ("delta_count", models.IntegerField(default=0)),
                ("delta_amount", models.DecimalField(decimal_places=2, default=Decimal("0"), max_digits=20)),
                (
                    "status",
                    models.CharField(
                        choices=[("draft", "Draft"), ("completed", "Completed")],
                        db_index=True,
                        default="draft",
                        max_length=16,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="created_reconciliation_runs",
                        to="wallets_demo.user",
                    ),
                ),
            ],
            options={"ordering": ("-created_at", "-id")},
        ),
        migrations.CreateModel(
            name="ReconciliationBreak",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("reference", models.CharField(blank=True, default="", max_length=128)),
                ("issue_type", models.CharField(default="amount_mismatch", max_length=64)),
                ("expected_amount", models.DecimalField(decimal_places=2, default=Decimal("0"), max_digits=20)),
                ("actual_amount", models.DecimalField(decimal_places=2, default=Decimal("0"), max_digits=20)),
                ("delta_amount", models.DecimalField(decimal_places=2, default=Decimal("0"), max_digits=20)),
                ("note", models.CharField(blank=True, default="", max_length=255)),
                (
                    "status",
                    models.CharField(
                        choices=[("open", "Open"), ("in_review", "In Review"), ("resolved", "Resolved")],
                        db_index=True,
                        default="open",
                        max_length=16,
                    ),
                ),
                ("resolved_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "assigned_to",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="assigned_reconciliation_breaks",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "created_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="created_reconciliation_breaks",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "merchant",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="reconciliation_breaks",
                        to="wallets_demo.merchant",
                    ),
                ),
                (
                    "resolved_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="resolved_reconciliation_breaks",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "run",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="breaks",
                        to="wallets_demo.reconciliationrun",
                    ),
                ),
            ],
            options={"ordering": ("-created_at", "-id")},
        ),
        migrations.CreateModel(
            name="SettlementPayout",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("payout_reference", models.CharField(max_length=48, unique=True)),
                ("payout_channel", models.CharField(default="bank_transfer", max_length=32)),
                ("destination_account", models.CharField(blank=True, default="", max_length=128)),
                ("amount", models.DecimalField(decimal_places=2, max_digits=20)),
                ("currency", models.CharField(default="USD", max_length=12)),
                (
                    "status",
                    models.CharField(
                        choices=[("pending", "Pending"), ("sent", "Sent"), ("settled", "Settled"), ("failed", "Failed")],
                        db_index=True,
                        default="pending",
                        max_length=16,
                    ),
                ),
                ("provider_response", models.JSONField(blank=True, default=dict)),
                ("approved_at", models.DateTimeField(blank=True, null=True)),
                ("sent_at", models.DateTimeField(blank=True, null=True)),
                ("settled_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "approved_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="approved_settlement_payouts",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "initiated_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="initiated_settlement_payouts",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "settlement",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="payout",
                        to="wallets_demo.merchantsettlementrecord",
                    ),
                ),
            ],
            options={"ordering": ("-created_at", "-id")},
        ),
        migrations.CreateModel(
            name="DisputeRefundRequest",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("amount", models.DecimalField(decimal_places=2, max_digits=20)),
                ("currency", models.CharField(default="USD", max_length=12)),
                ("reason", models.CharField(blank=True, default="", max_length=255)),
                (
                    "status",
                    models.CharField(
                        choices=[("pending", "Pending"), ("approved", "Approved"), ("rejected", "Rejected"), ("executed", "Executed"), ("failed", "Failed")],
                        db_index=True,
                        default="pending",
                        max_length=16,
                    ),
                ),
                ("maker_note", models.TextField(blank=True, default="")),
                ("checker_note", models.TextField(blank=True, default="")),
                ("error_message", models.TextField(blank=True, default="")),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("decided_at", models.DateTimeField(blank=True, null=True)),
                (
                    "case",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="refund_requests",
                        to="wallets_demo.operationcase",
                    ),
                ),
                (
                    "checker",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="checked_refund_requests",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "customer",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="refund_requests",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "executed_event",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="executed_refund_requests",
                        to="wallets_demo.merchantcashflowevent",
                    ),
                ),
                (
                    "maker",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="made_refund_requests",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "merchant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="refund_requests",
                        to="wallets_demo.merchant",
                    ),
                ),
                (
                    "source_cashflow_event",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="refund_requests",
                        to="wallets_demo.merchantcashflowevent",
                    ),
                ),
            ],
            options={"ordering": ("-created_at", "-id")},
        ),
    ]
