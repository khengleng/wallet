from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("wallets_demo", "0007_fx_rate"),
    ]

    operations = [
        migrations.AddField(
            model_name="fxrate",
            name="source_provider",
            field=models.CharField(blank=True, default="", max_length=64),
        ),
        migrations.AddField(
            model_name="fxrate",
            name="source_reference",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
    ]
