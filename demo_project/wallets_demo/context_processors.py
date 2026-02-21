def organization_settings(request):
    """Inject organization_name from OperationSetting into every template context."""
    try:
        from .models import OperationSetting
        settings_row = OperationSetting.get_solo()
        return {
            "org_name": settings_row.organization_name or "DJ Wallet",
        }
    except Exception:
        return {"org_name": "DJ Wallet"}
