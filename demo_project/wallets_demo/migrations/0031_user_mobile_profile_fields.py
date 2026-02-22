from django.db import migrations, models

import wallets_demo.models


class Migration(migrations.Migration):

    dependencies = [
        ("wallets_demo", "0030_customer_class_upgrade_request_and_monthly_limits"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="mobile_preferences",
            field=models.JSONField(
                blank=True,
                default=wallets_demo.models.default_mobile_user_preferences,
            ),
        ),
        migrations.AddField(
            model_name="user",
            name="profile_picture_url",
            field=models.URLField(blank=True, default=""),
        ),
    ]
