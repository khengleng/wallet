import json
from urllib.parse import urlparse

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


PRIVILEGED_ROLES = ("super_admin", "admin", "finance", "risk", "operation")


def _is_https_url(value: str) -> bool:
    if not value:
        return False
    parsed = urlparse(value)
    return parsed.scheme == "https" and bool(parsed.netloc)


def _has_wildcard(value: str) -> bool:
    return "*" in (value or "")


class Command(BaseCommand):
    help = "Validate Keycloak hardening baseline configuration."

    def add_arguments(self, parser):
        parser.add_argument("--json", action="store_true", help="Output as JSON.")
        parser.add_argument(
            "--no-fail-on-issues",
            action="store_true",
            help="Do not return non-zero exit when hardening gaps are found.",
        )

    def handle(self, *args, **options):
        issues: list[str] = []
        warnings: list[str] = []

        auth_mode = getattr(settings, "AUTH_MODE", "").lower()
        if auth_mode != "keycloak_oidc":
            warnings.append(
                f"AUTH_MODE is '{auth_mode}'. Keycloak hardening checks are most relevant in 'keycloak_oidc' mode."
            )

        keycloak_base = getattr(settings, "KEYCLOAK_BASE_URL", "")
        keycloak_realm = getattr(settings, "KEYCLOAK_REALM", "")
        client_id = getattr(settings, "KEYCLOAK_CLIENT_ID", "")
        redirect_uri = getattr(settings, "KEYCLOAK_REDIRECT_URI", "")
        post_logout_redirect_uri = getattr(settings, "KEYCLOAK_POST_LOGOUT_REDIRECT_URI", "")
        scopes = (getattr(settings, "KEYCLOAK_SCOPES", "") or "").split()
        introspection_timeout = float(getattr(settings, "KEYCLOAK_INTROSPECTION_TIMEOUT_SECONDS", 3.0))
        session_check_interval = int(getattr(settings, "KEYCLOAK_SESSION_CHECK_INTERVAL_SECONDS", 120))
        role_group_map = getattr(settings, "KEYCLOAK_ROLE_GROUP_MAP", {}) or {}

        if not _is_https_url(keycloak_base):
            issues.append("KEYCLOAK_BASE_URL must be an HTTPS URL.")
        if not keycloak_realm:
            issues.append("KEYCLOAK_REALM must be set.")
        if not client_id:
            issues.append("KEYCLOAK_CLIENT_ID must be set.")

        if not _is_https_url(redirect_uri):
            issues.append("KEYCLOAK_REDIRECT_URI must be an HTTPS URL.")
        elif _has_wildcard(redirect_uri):
            issues.append("KEYCLOAK_REDIRECT_URI must not contain wildcard patterns.")

        if post_logout_redirect_uri:
            if not _is_https_url(post_logout_redirect_uri):
                issues.append("KEYCLOAK_POST_LOGOUT_REDIRECT_URI must be HTTPS when set.")
            elif _has_wildcard(post_logout_redirect_uri):
                issues.append("KEYCLOAK_POST_LOGOUT_REDIRECT_URI must not contain wildcard patterns.")

        for required_scope in ("openid", "profile", "email"):
            if required_scope not in scopes:
                issues.append(f"KEYCLOAK_SCOPES must include '{required_scope}'.")

        if introspection_timeout > 5:
            warnings.append(
                f"KEYCLOAK_INTROSPECTION_TIMEOUT_SECONDS={introspection_timeout} is high; recommended <= 5."
            )
        if session_check_interval > 300:
            warnings.append(
                f"KEYCLOAK_SESSION_CHECK_INTERVAL_SECONDS={session_check_interval} is high; recommended <= 300."
            )

        for role in PRIVILEGED_ROLES:
            if role not in role_group_map:
                issues.append(
                    f"KEYCLOAK_ROLE_GROUP_MAP must include privileged role mapping for '{role}'."
                )

        assertions = {
            "brute_force_detection": (getattr(settings, "KEYCLOAK_ASSERT_BRUTE_FORCE_DETECTION", "") or "").lower(),
            "email_verification": (getattr(settings, "KEYCLOAK_ASSERT_EMAIL_VERIFICATION", "") or "").lower(),
            "otp_required_for_privileged": (
                getattr(settings, "KEYCLOAK_ASSERT_OTP_REQUIRED_FOR_PRIVILEGED", "") or ""
            ).lower(),
            "strict_redirects": (getattr(settings, "KEYCLOAK_ASSERT_STRICT_REDIRECTS", "") or "").lower(),
        }
        for name, value in assertions.items():
            if value != "true":
                warnings.append(
                    f"Set {name.upper()} assertion env to true to attest realm hardening state."
                )

        payload = {
            "ok": not issues,
            "issues": issues,
            "warnings": warnings,
            "auth_mode": auth_mode,
        }

        if options["json"]:
            self.stdout.write(json.dumps(payload, sort_keys=True))
        else:
            self.stdout.write(
                f"Keycloak hardening check: {'PASS' if payload['ok'] else 'FAIL'}; "
                f"issues={len(issues)} warnings={len(warnings)}"
            )
            for msg in issues:
                self.stdout.write(f"ERROR: {msg}")
            for msg in warnings:
                self.stdout.write(f"WARN: {msg}")

        if issues and not options["no_fail_on_issues"]:
            raise CommandError("Keycloak hardening baseline failed.")
