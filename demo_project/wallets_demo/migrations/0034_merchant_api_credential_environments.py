from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("wallets_demo", "0033_tenant_foundation"),
    ]

    operations = [
        migrations.AddField(
            model_name="merchantapicredential",
            name="live_enabled",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="merchantapicredential",
            name="sandbox_enabled",
            field=models.BooleanField(default=True),
        ),
    ]
