from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("wallets_demo", "0011_merchant_cashflow_event"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="wallet_type",
            field=models.CharField(
                choices=[
                    ("P", "Personal"),
                    ("B", "Business"),
                    ("C", "Customer"),
                    ("G", "Government"),
                ],
                default="C",
                max_length=1,
            ),
        ),
        migrations.AddField(
            model_name="merchant",
            name="wallet_type",
            field=models.CharField(
                choices=[("B", "Business"), ("G", "Government")],
                default="B",
                max_length=1,
            ),
        ),
    ]
