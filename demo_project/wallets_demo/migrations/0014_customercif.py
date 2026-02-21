from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("wallets_demo", "0013_analytics_event"),
    ]

    operations = [
        migrations.CreateModel(
            name="CustomerCIF",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("cif_no", models.CharField(max_length=40, unique=True)),
                ("legal_name", models.CharField(max_length=128)),
                ("mobile_no", models.CharField(blank=True, default="", max_length=40)),
                ("email", models.EmailField(blank=True, default="", max_length=254)),
                (
                    "status",
                    models.CharField(
                        choices=[("active", "Active"), ("blocked", "Blocked"), ("closed", "Closed")],
                        default="active",
                        max_length=16,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="created_customer_cifs",
                        to="wallets_demo.user",
                    ),
                ),
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="customer_cif",
                        to="wallets_demo.user",
                    ),
                ),
            ],
            options={"ordering": ("cif_no",)},
        ),
    ]
