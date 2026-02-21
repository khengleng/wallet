from django.core.management.base import BaseCommand

from wallets_demo.rbac import ROLE_DEFINITIONS, seed_role_groups


class Command(BaseCommand):
    help = "Create or update RBAC role groups and permissions."

    def handle(self, *args, **options):
        result = seed_role_groups()
        created = ", ".join(result["created_groups"]) or "none"
        updated = ", ".join(result["updated_groups"]) or "none"
        missing = ", ".join(result["missing_permissions"]) or "none"

        self.stdout.write(self.style.SUCCESS("RBAC roles synchronized."))
        self.stdout.write(f"Created groups: {created}")
        self.stdout.write(f"Updated groups: {updated}")
        self.stdout.write(f"Missing permissions: {missing}")
        self.stdout.write(
            "Available roles: " + ", ".join(sorted(ROLE_DEFINITIONS.keys()))
        )
