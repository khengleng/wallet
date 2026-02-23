from django.db import migrations, models

import wallets_demo.models


class Migration(migrations.Migration):

    dependencies = [
        ("wallets_demo", "0031_user_mobile_profile_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="operationsetting",
            name="action_visibility_rules",
            field=models.JSONField(
                blank=True,
                default=wallets_demo.models.default_action_visibility_rules,
                help_text=(
                    "Optional action visibility overrides by action key. "
                    'Format: {"action_key": ["role1", "role2"]}.'
                ),
            ),
        ),
        migrations.AddField(
            model_name="operationsetting",
            name="field_visibility_rules",
            field=models.JSONField(
                blank=True,
                default=wallets_demo.models.default_field_visibility_rules,
                help_text=(
                    "Optional field visibility overrides by field key. "
                    'Format: {"field_key": ["role1", "role2"]}.'
                ),
            ),
        ),
    ]

