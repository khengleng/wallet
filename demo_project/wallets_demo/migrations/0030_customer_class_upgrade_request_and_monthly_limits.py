from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("wallets_demo", "0029_tariffrule"),
    ]

    operations = [
        migrations.AddField(
            model_name="serviceclasspolicy",
            name="monthly_amount_limit",
            field=models.DecimalField(blank=True, decimal_places=2, max_digits=20, null=True),
        ),
        migrations.AddField(
            model_name="serviceclasspolicy",
            name="monthly_txn_count_limit",
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.CreateModel(
            name="CustomerClassUpgradeRequest",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("status", models.CharField(choices=[("pending", "Pending"), ("approved", "Approved"), ("rejected", "Rejected")], db_index=True, default="pending", max_length=16)),
                ("maker_note", models.TextField(blank=True, default="")),
                ("checker_note", models.TextField(blank=True, default="")),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("decided_at", models.DateTimeField(blank=True, null=True)),
                ("checker", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name="checked_class_upgrade_requests", to="wallets_demo.user")),
                ("cif", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="class_upgrade_requests", to="wallets_demo.customercif")),
                ("from_service_class", models.ForeignKey(blank=True, limit_choices_to={"entity_type": "customer"}, null=True, on_delete=django.db.models.deletion.PROTECT, related_name="class_upgrade_from_requests", to="wallets_demo.serviceclasspolicy")),
                ("maker", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="made_class_upgrade_requests", to="wallets_demo.user")),
                ("to_service_class", models.ForeignKey(limit_choices_to={"entity_type": "customer"}, on_delete=django.db.models.deletion.PROTECT, related_name="class_upgrade_to_requests", to="wallets_demo.serviceclasspolicy")),
            ],
            options={
                "ordering": ("-created_at",),
            },
        ),
    ]
