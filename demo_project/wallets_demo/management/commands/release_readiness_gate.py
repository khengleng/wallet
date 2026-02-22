import json

from django.core.management.base import BaseCommand, CommandError

from wallets_demo.release_readiness import release_readiness_snapshot


class Command(BaseCommand):
    help = "Evaluate release readiness gate for business operations."

    def add_arguments(self, parser):
        parser.add_argument(
            "--json",
            action="store_true",
            help="Print readiness result as JSON.",
        )
        parser.add_argument(
            "--no-fail-on-issues",
            action="store_true",
            help="Do not return non-zero exit code when gate checks fail.",
        )

    def handle(self, *args, **options):
        snapshot = release_readiness_snapshot()
        if options["json"]:
            self.stdout.write(json.dumps(snapshot, sort_keys=True))
        else:
            self.stdout.write(
                "Release readiness snapshot: "
                f"pending_refunds={snapshot['pending_refunds']}, "
                f"failed_payouts={snapshot['failed_payouts']}, "
                f"open_recon_breaks={snapshot['open_recon_breaks']}, "
                f"open_high_alerts={snapshot['open_high_alerts']}, "
                f"gate={'PASS' if snapshot['is_ready'] else 'FAIL'}"
            )

        if not options["no_fail_on_issues"] and not snapshot["is_ready"]:
            raise CommandError(
                "Release readiness gate failed: "
                + ", ".join(snapshot["failed_checks"])
            )
