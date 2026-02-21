from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("wallets_demo", "0005_security_models"),
    ]

    operations = [
        migrations.AddField(
            model_name="approvalrequest",
            name="currency",
            field=models.CharField(default="USD", max_length=12),
        ),
        migrations.AddField(
            model_name="journalentry",
            name="currency",
            field=models.CharField(default="USD", max_length=12),
        ),
    ]
