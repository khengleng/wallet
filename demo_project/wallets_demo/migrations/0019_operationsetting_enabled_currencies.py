from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("wallets_demo", "0018_operationsetting"),
    ]

    operations = [
        migrations.AddField(
            model_name="operationsetting",
            name="enabled_currencies",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="List of active currency codes on this platform. Leave empty to use SUPPORTED_CURRENCIES setting.",
            ),
        ),
    ]
