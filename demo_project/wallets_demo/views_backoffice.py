"""Back-office view exports (phase 1 split from monolithic views module)."""

from . import views as legacy

backoffice = legacy.backoffice
backoffice_audit_export = legacy.backoffice_audit_export
rbac_management = legacy.rbac_management
fx_management = legacy.fx_management
wallet_management = legacy.wallet_management
merchant_portal = legacy.merchant_portal
accounting_dashboard = legacy.accounting_dashboard
accounting_post_entry = legacy.accounting_post_entry
