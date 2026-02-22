from __future__ import annotations

from django.apps import apps

from .rbac import user_has_any_role

DEFAULT_MENU_ROLE_RULES: dict[str, tuple[str, ...]] = {
    "wallet_management": (
        "super_admin",
        "admin",
        "operation",
        "finance",
        "customer_service",
        "risk",
        "treasury",
        "sales",
    ),
    "backoffice": ("admin", "super_admin", "finance", "treasury", "customer_service", "risk", "operation", "sales"),
    "operations_center": ("super_admin", "admin", "operation", "customer_service", "risk", "finance", "sales"),
    "case_management": ("super_admin", "admin", "operation", "customer_service", "risk", "finance", "sales"),
    "ops_work_queue": ("super_admin", "admin", "operation", "customer_service", "risk", "finance", "treasury"),
    "treasury_dashboard": ("admin", "super_admin", "finance", "treasury", "risk", "operation"),
    "accounting_dashboard": ("finance", "treasury", "admin", "super_admin"),
    "settlement_operations": ("super_admin", "admin", "operation", "finance", "treasury", "risk"),
    "reconciliation_workbench": ("super_admin", "admin", "operation", "finance", "risk", "treasury"),
    "approval_matrix": ("super_admin", "admin", "risk", "finance", "operation", "treasury"),
    "documents_center": ("super_admin", "admin", "operation", "risk", "finance", "customer_service", "sales", "treasury"),
    "fx_management": ("finance", "treasury", "admin", "super_admin"),
    "rbac_management": ("admin", "super_admin"),
    "operations_settings": ("super_admin",),
}

DEFAULT_SENSITIVE_ROLES: tuple[str, ...] = (
    "super_admin",
    "admin",
    "finance",
    "treasury",
    "risk",
)

DEFAULT_SENSITIVE_DOMAIN_RULES: dict[str, tuple[str, ...]] = {
    "wallet_balance": DEFAULT_SENSITIVE_ROLES,
    "transaction_amount": DEFAULT_SENSITIVE_ROLES,
    "settlement_amount": DEFAULT_SENSITIVE_ROLES,
    "accounting_amount": DEFAULT_SENSITIVE_ROLES,
    "treasury_amount": DEFAULT_SENSITIVE_ROLES,
    "customer_pii": ("super_admin", "admin", "risk", "operation"),
}


def _get_operation_setting():
    OperationSetting = apps.get_model("wallets_demo", "OperationSetting")
    try:
        return OperationSetting.get_solo()
    except Exception:
        return None


def _normalize_roles(raw_roles) -> tuple[str, ...]:
    if not isinstance(raw_roles, (list, tuple)):
        return ()
    roles = tuple(sorted({str(role).strip() for role in raw_roles if str(role).strip()}))
    return roles


def allowed_roles_for_menu(menu_key: str) -> tuple[str, ...]:
    defaults = DEFAULT_MENU_ROLE_RULES.get(menu_key, ())
    settings_row = _get_operation_setting()
    if settings_row is None:
        return defaults

    rules = settings_row.nav_visibility_rules
    if not isinstance(rules, dict):
        return defaults

    override = _normalize_roles(rules.get(menu_key))
    if override:
        return override
    return defaults


def user_can_view_menu(user, menu_key: str) -> bool:
    if not getattr(user, "is_authenticated", False):
        return False
    roles = allowed_roles_for_menu(menu_key)
    if not roles:
        return False
    return user_has_any_role(user, roles)


def sensitive_data_roles() -> tuple[str, ...]:
    settings_row = _get_operation_setting()
    if settings_row is None:
        return DEFAULT_SENSITIVE_ROLES
    configured = _normalize_roles(getattr(settings_row, "sensitive_data_roles", []))
    if configured:
        return configured
    return DEFAULT_SENSITIVE_ROLES


def user_can_view_sensitive(user) -> bool:
    if not getattr(user, "is_authenticated", False):
        return False
    return user_has_any_role(user, sensitive_data_roles())


def sensitive_roles_for_domain(domain_key: str) -> tuple[str, ...]:
    defaults = DEFAULT_SENSITIVE_DOMAIN_RULES.get(domain_key, DEFAULT_SENSITIVE_ROLES)
    settings_row = _get_operation_setting()
    if settings_row is None:
        return defaults
    raw = getattr(settings_row, "sensitive_visibility_rules", {})
    if not isinstance(raw, dict):
        return defaults
    configured = _normalize_roles(raw.get(domain_key))
    if configured:
        return configured
    return defaults


def user_can_view_sensitive_domain(user, domain_key: str) -> bool:
    if not getattr(user, "is_authenticated", False):
        return False
    return user_has_any_role(user, sensitive_roles_for_domain(domain_key))


def mask_sensitive_value(value, user, mask: str = "****", domain_key: str = ""):
    can_view = user_can_view_sensitive_domain(user, domain_key) if domain_key else user_can_view_sensitive(user)
    if can_view:
        return value
    return mask
