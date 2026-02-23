def organization_settings(request):
    """Inject organization_name from OperationSetting into every template context."""
    try:
        from .models import OperationSetting
        from django.conf import settings as django_settings
        settings_row = OperationSetting.get_solo()
        return {
            "org_name": settings_row.organization_name or "DJ Wallet",
            "release_short_sha": getattr(django_settings, "RELEASE_SHORT_SHA", "unknown"),
            "release_version": getattr(django_settings, "RELEASE_VERSION", "unknown"),
        }
    except Exception:
        return {
            "org_name": "DJ Wallet",
            "release_short_sha": "unknown",
            "release_version": "unknown",
        }
