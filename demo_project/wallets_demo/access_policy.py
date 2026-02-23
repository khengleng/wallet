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
    "policy_hub": ("super_admin", "admin", "risk", "finance", "operation"),
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

DEFAULT_ACTION_ROLE_RULES: dict[str, tuple[str, ...]] = {
    "wallet.cif_onboard": ("super_admin", "admin", "operation", "customer_service"),
    "wallet.open_user": ("super_admin", "admin", "operation", "finance"),
    "wallet.open_merchant": ("super_admin", "admin", "operation", "finance"),
    "wallet.adjust_user": ("super_admin", "admin", "operation", "finance"),
    "wallet.adjust_merchant": ("super_admin", "admin", "operation", "finance"),
    "wallet.toggle_freeze": ("super_admin", "admin", "operation", "risk"),
    "merchant.create": ("super_admin", "admin", "operation", "sales"),
    "merchant.portal_api_update": ("super_admin", "admin", "operation", "risk"),
    "merchant.kyb_submit": ("super_admin", "admin", "operation", "sales"),
    "merchant.kyb_decide": ("super_admin", "admin", "risk"),
    "case.create": ("super_admin", "admin", "operation", "customer_service"),
    "case.update": ("super_admin", "admin", "operation", "customer_service", "risk"),
    "rbac.manage": ("super_admin", "admin"),
    "settings.manage": ("super_admin",),
    "form.treasury_transfer_request": ("super_admin", "admin", "finance", "treasury"),
    "form.treasury_account_upsert": ("super_admin", "admin", "treasury"),
    "form.treasury_account_toggle": ("super_admin", "admin", "treasury"),
    "form.treasury_policy_update": ("super_admin", "admin", "treasury"),
    "form.period_governance": ("super_admin", "admin", "finance", "treasury", "risk"),
    "form.fx_rate_create": ("super_admin", "admin", "finance", "treasury"),
    "form.coa_create": ("super_admin", "admin", "finance", "treasury"),
    "form.journal_create": ("super_admin", "admin", "finance", "treasury"),
    "form.journal_submit_for_checker": ("super_admin", "admin", "finance", "treasury"),
    "form.journal_approval_decision": ("super_admin", "admin", "finance", "risk"),
    "form.journal_reversal_request": ("super_admin", "admin", "finance", "treasury"),
    "form.journal_reclass_request": ("super_admin", "admin", "finance", "treasury"),
    "form.journal_export": ("super_admin", "admin", "finance", "treasury"),
    "form.merchant_create": ("super_admin", "admin", "operation", "sales", "finance"),
    "form.merchant_update": ("super_admin", "admin", "operation", "sales", "finance"),
    "form.merchant_kyb_submit": ("super_admin", "admin", "operation", "sales", "finance", "customer_service"),
    "form.merchant_kyb_decision": ("super_admin", "admin", "risk"),
    "form.merchant_fee_rule_upsert": ("super_admin", "admin", "finance", "operation"),
    "form.merchant_risk_update": ("super_admin", "admin", "risk"),
    "form.merchant_api_rotate": ("super_admin", "admin", "risk"),
    "form.merchant_settlement_create": ("super_admin", "admin", "operation", "finance"),
    "form.settlement_automation_run": ("super_admin", "admin", "operation", "finance"),
    "form.merchant_settlement_update": ("super_admin", "admin", "operation", "finance"),
    "form.dispute_refund_submit": ("super_admin", "admin", "operation", "finance", "customer_service"),
    "form.dispute_refund_decision": ("super_admin", "admin", "risk"),
    "form.refund_escalation_run": ("super_admin", "admin", "risk", "operation"),
    "form.case_sla_escalation_run": ("super_admin", "admin", "operation", "risk"),
    "form.settlement_payout_submit": ("super_admin", "admin", "finance", "treasury"),
    "form.settlement_payout_decision": ("super_admin", "admin", "risk"),
    "form.reconciliation_run_create": ("super_admin", "admin", "operation", "finance", "risk"),
    "form.reconciliation_break_update": ("super_admin", "admin", "operation", "finance", "risk"),
    "form.chargeback_create": ("super_admin", "admin", "operation", "risk", "customer_service"),
    "form.chargeback_update": ("super_admin", "admin", "operation", "risk"),
    "form.chargeback_evidence_add": ("super_admin", "admin", "operation", "risk", "customer_service"),
    "form.accounting_period_close_upsert": ("super_admin", "admin", "finance", "risk"),
    "form.journal_backdate_request": ("super_admin", "admin", "finance", "operation"),
    "form.journal_backdate_decision": ("super_admin", "admin", "risk"),
    "form.sanction_screening_run": ("super_admin", "admin", "risk", "operation"),
    "form.monitoring_alert_update": ("super_admin", "admin", "risk", "operation", "finance"),
    "form.merchant_webhook_validate": ("super_admin", "admin", "operation", "risk", "finance"),
    "form.access_review_run": ("super_admin", "admin", "risk"),
    "form.access_review_update": ("super_admin", "admin", "risk"),
    "form.data_retention_purge": ("super_admin", "admin", "risk"),
    "form.release_readiness_check": ("super_admin", "admin", "operation", "risk", "finance"),
    "form.case_create": ("super_admin", "admin", "operation", "customer_service", "risk", "finance", "sales"),
    "form.user_wallet_type_update": ("super_admin", "admin", "operation", "customer_service"),
    "form.case_update": ("super_admin", "admin", "operation", "customer_service", "risk", "finance", "sales"),
    "form.loyalty_event_create": ("super_admin", "admin", "operation", "customer_service", "sales", "finance"),
    "form.cashflow_event_create": ("super_admin", "admin", "operation", "finance", "risk"),
    "form.batch_generate": ("super_admin", "admin", "finance", "treasury", "operation"),
    "form.batch_status_update": ("super_admin", "admin", "finance", "treasury", "operation"),
    "form.settlement_exception_create": ("super_admin", "admin", "operation", "finance", "risk"),
    "form.settlement_exception_update": ("super_admin", "admin", "operation", "finance", "risk"),
    "form.reconciliation_match_update": ("super_admin", "admin", "operation", "finance", "risk"),
    "form.reconciliation_resolution_request": ("super_admin", "admin", "operation", "finance", "risk"),
    "form.reconciliation_resolution_decision": ("super_admin", "admin", "risk", "finance"),
    "form.reconciliation_evidence_add": ("super_admin", "admin", "operation", "finance", "risk"),
    "form.merchant_portal_update_webhook": ("super_admin", "admin", "operation", "risk"),
    "form.wallet_open_user": ("super_admin", "admin", "operation", "finance"),
    "form.wallet_open_merchant": ("super_admin", "admin", "operation", "finance"),
    "form.wallet_toggle_freeze": ("super_admin", "admin", "operation", "risk"),
    "form.wallet_adjust_user": ("super_admin", "admin", "operation", "finance"),
    "form.cif_onboard": ("super_admin", "admin", "operation", "customer_service"),
    "form.wallet_adjust_merchant": ("super_admin", "admin", "operation", "finance"),
    "form.policy_upsert": ("super_admin", "admin", "risk", "finance", "operation"),
    "form.policy_assign_customer": ("super_admin", "admin", "risk", "finance", "operation"),
    "form.policy_upgrade_customer_request": ("super_admin", "admin", "operation", "finance"),
    "form.policy_upgrade_customer_decision": ("super_admin", "admin", "risk", "finance"),
    "form.policy_assign_merchant": ("super_admin", "admin", "risk", "finance", "operation"),
    "form.tariff_upsert": ("super_admin", "admin", "risk", "finance", "operation"),
    "form.approval_rule_upsert": ("super_admin", "admin", "risk", "finance", "operation", "treasury"),
    "form.toggle": ("super_admin", "admin", "risk", "finance", "operation", "treasury"),
    "form.document_upload": ("super_admin", "admin", "operation", "risk", "finance", "customer_service", "sales", "treasury"),
    "form.case_note_add": ("super_admin", "admin", "operation", "customer_service", "risk", "finance", "sales", "treasury"),
    "form.case_document_add": ("super_admin", "admin", "operation", "customer_service", "risk", "finance", "sales", "treasury"),
}

DEFAULT_FIELD_ROLE_RULES: dict[str, tuple[str, ...]] = {
    "wallet.customer.mobile_no": ("super_admin", "admin", "operation", "customer_service", "risk"),
    "wallet.customer.email": ("super_admin", "admin", "operation", "customer_service", "risk"),
    "merchant.contact.mobile_no": ("super_admin", "admin", "operation", "sales", "risk"),
    "merchant.contact.email": ("super_admin", "admin", "operation", "sales", "risk"),
    "ops.case.reporter_contact": ("super_admin", "admin", "operation", "customer_service", "risk"),
    "merchant.api.key_id": ("super_admin", "admin", "operation", "risk"),
    "merchant.api.webhook_url": ("super_admin", "admin", "operation", "risk"),
    "merchant.webhook.nonce": ("super_admin", "admin", "operation", "risk"),
    "settlement.payout.destination_account": ("super_admin", "admin", "operation", "finance", "treasury", "risk"),
    "ops.case.description": ("super_admin", "admin", "operation", "risk"),
    "ops.case.note": ("super_admin", "admin", "operation", "risk"),
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


def allowed_roles_for_action(action_key: str) -> tuple[str, ...]:
    defaults = DEFAULT_ACTION_ROLE_RULES.get(action_key, ())
    settings_row = _get_operation_setting()
    if settings_row is None:
        return defaults
    raw = getattr(settings_row, "action_visibility_rules", {})
    if not isinstance(raw, dict):
        return defaults
    configured = _normalize_roles(raw.get(action_key))
    if configured:
        return configured
    return defaults


def user_can_do_action(user, action_key: str) -> bool:
    if not getattr(user, "is_authenticated", False):
        return False
    roles = allowed_roles_for_action(action_key)
    if not roles:
        return False
    return user_has_any_role(user, roles)


def allowed_roles_for_field(field_key: str) -> tuple[str, ...]:
    defaults = DEFAULT_FIELD_ROLE_RULES.get(field_key, ())
    settings_row = _get_operation_setting()
    if settings_row is None:
        return defaults
    raw = getattr(settings_row, "field_visibility_rules", {})
    if not isinstance(raw, dict):
        return defaults
    configured = _normalize_roles(raw.get(field_key))
    if configured:
        return configured
    return defaults


def user_can_view_field(user, field_key: str) -> bool:
    if not getattr(user, "is_authenticated", False):
        return False
    roles = allowed_roles_for_field(field_key)
    if not roles:
        return False
    return user_has_any_role(user, roles)


def mask_sensitive_value(value, user, mask: str = "****", domain_key: str = ""):
    can_view = user_can_view_sensitive_domain(user, domain_key) if domain_key else user_can_view_sensitive(user)
    if can_view:
        return value
    return mask
