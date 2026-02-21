from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):
    dependencies = [
        ("wallets_demo", "0004_accounting_models"),
    ]

    operations = [
        migrations.CreateModel(
            name="BackofficeAuditLog",
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
                ("action", models.CharField(db_index=True, max_length=128)),
                ("target_type", models.CharField(blank=True, default="", max_length=64)),
                ("target_id", models.CharField(blank=True, default="", max_length=64)),
                ("ip_address", models.GenericIPAddressField(blank=True, null=True)),
                ("user_agent", models.CharField(blank=True, default="", max_length=255)),
                ("metadata_json", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                (
                    "actor",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="backoffice_audit_logs",
                        to="wallets_demo.user",
                    ),
                ),
            ],
            options={"ordering": ("-created_at",)},
        ),
        migrations.CreateModel(
            name="LoginLockout",
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
                ("username", models.CharField(db_index=True, max_length=150)),
                ("ip_address", models.GenericIPAddressField()),
                ("failed_attempts", models.PositiveIntegerField(default=0)),
                ("first_failed_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("lock_until", models.DateTimeField(blank=True, db_index=True, null=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "ordering": ("-updated_at",),
                "unique_together": {("username", "ip_address")},
            },
        ),
    ]
