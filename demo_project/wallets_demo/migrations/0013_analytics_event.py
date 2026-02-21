from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("wallets_demo", "0012_wallet_type_classification"),
    ]

    operations = [
        migrations.CreateModel(
            name="AnalyticsEvent",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "source",
                    models.CharField(
                        choices=[("web", "Web"), ("api", "API"), ("mobile", "Mobile")],
                        default="web",
                        max_length=16,
                    ),
                ),
                ("event_name", models.CharField(db_index=True, max_length=128)),
                ("session_id", models.CharField(blank=True, default="", max_length=64)),
                ("external_id", models.CharField(blank=True, default="", max_length=128)),
                ("properties", models.JSONField(blank=True, default=dict)),
                ("sent_to_clevertap", models.BooleanField(default=False)),
                ("clevertap_error", models.CharField(blank=True, default="", max_length=255)),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                (
                    "user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="analytics_events",
                        to="wallets_demo.user",
                    ),
                ),
            ],
            options={"ordering": ("-created_at", "-id")},
        ),
    ]
