from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


def seed_default_tenant_and_backfill(apps, schema_editor):
    Tenant = apps.get_model("wallets_demo", "Tenant")
    User = apps.get_model("wallets_demo", "User")
    Merchant = apps.get_model("wallets_demo", "Merchant")
    CustomerCIF = apps.get_model("wallets_demo", "CustomerCIF")
    default_code = str(getattr(settings, "MULTITENANCY_DEFAULT_TENANT_CODE", "default")).strip().lower() or "default"
    tenant, _created = Tenant.objects.get_or_create(
        code=default_code,
        defaults={"name": "Default Tenant", "is_active": True},
    )
    User.objects.filter(tenant__isnull=True).update(tenant=tenant)
    Merchant.objects.filter(tenant__isnull=True).update(tenant=tenant)
    for cif in CustomerCIF.objects.filter(tenant__isnull=True).iterator():
        user_tenant_id = (
            User.objects.filter(id=cif.user_id).values_list("tenant_id", flat=True).first()
        )
        cif.tenant_id = user_tenant_id or tenant.id
        cif.save(update_fields=["tenant"])


class Migration(migrations.Migration):

    dependencies = [
        ("wallets_demo", "0032_operationsetting_action_field_visibility_rules"),
    ]

    operations = [
        migrations.CreateModel(
            name="Tenant",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("code", models.CharField(db_index=True, max_length=48, unique=True)),
                ("name", models.CharField(max_length=128)),
                ("is_active", models.BooleanField(db_index=True, default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "ordering": ("code",),
            },
        ),
        migrations.AddField(
            model_name="user",
            name="tenant",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="users",
                to="wallets_demo.tenant",
            ),
        ),
        migrations.AddField(
            model_name="merchant",
            name="tenant",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="merchants",
                to="wallets_demo.tenant",
            ),
        ),
        migrations.AddField(
            model_name="customercif",
            name="tenant",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                related_name="customer_cifs",
                to="wallets_demo.tenant",
            ),
        ),
        migrations.RunPython(
            seed_default_tenant_and_backfill,
            reverse_code=migrations.RunPython.noop,
        ),
    ]

