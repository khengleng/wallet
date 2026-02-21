from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from wallets_demo.models import AnalyticsEvent, BackofficeAuditLog, LoginLockout


class Command(BaseCommand):
    help = "Purge aged operational data based on retention days."

    def add_arguments(self, parser):
        parser.add_argument("--days", type=int, default=365, help="Retention window in days.")
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report counts without deleting records.",
        )

    def handle(self, *args, **options):
        days = max(int(options["days"]), 1)
        dry_run = bool(options["dry_run"])
        cutoff = timezone.now() - timedelta(days=days)

        analytics_qs = AnalyticsEvent.objects.filter(created_at__lt=cutoff)
        lockout_qs = LoginLockout.objects.filter(updated_at__lt=cutoff)
        audit_qs = BackofficeAuditLog.objects.filter(created_at__lt=cutoff)
        counts = {
            "analytics": analytics_qs.count(),
            "lockouts": lockout_qs.count(),
            "audit_logs": audit_qs.count(),
        }

        if not dry_run:
            analytics_qs.delete()
            lockout_qs.delete()
            # Keep audit logs immutable; intentionally retained.

        self.stdout.write(
            self.style.SUCCESS(
                (
                    f"purge_operational_data {'dry-run' if dry_run else 'executed'} "
                    f"(days={days}) analytics={counts['analytics']} "
                    f"lockouts={counts['lockouts']} audit_logs={counts['audit_logs']} "
                    "(audit logs retained)"
                )
            )
        )
