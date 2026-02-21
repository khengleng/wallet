import django.db.models.deletion
from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):
    dependencies = [
        ("wallets_demo", "0006_multi_currency_fields"),
    ]

    operations = [
        migrations.CreateModel(
            name="FxRate",
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
                ("base_currency", models.CharField(max_length=12)),
                ("quote_currency", models.CharField(max_length=12)),
                ("rate", models.DecimalField(decimal_places=8, max_digits=20)),
                (
                    "effective_at",
                    models.DateTimeField(db_index=True, default=django.utils.timezone.now),
                ),
                ("is_active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="created_fx_rates",
                        to="wallets_demo.user",
                    ),
                ),
            ],
            options={"ordering": ("-effective_at", "-id")},
        ),
        migrations.AddIndex(
            model_name="fxrate",
            index=models.Index(
                fields=["base_currency", "quote_currency", "effective_at"],
                name="fx_pair_effective_idx",
            ),
        ),
    ]
