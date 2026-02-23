from django.urls import path
from . import views
from . import views_auth
from . import views_backoffice
from . import views_mobile
from . import views_operations
from . import views_playground

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('version', views.version_info, name='version_info'),
    path('api/mobile/bootstrap/', views_mobile.mobile_bootstrap, name='mobile_bootstrap'),
    path('api/mobile/profile/', views_mobile.mobile_profile, name='mobile_profile'),
    path('api/mobile/personalization/', views_mobile.mobile_personalization, name='mobile_personalization'),
    path(
        'api/mobile/personalization/signals/',
        views_mobile.mobile_personalization_signals,
        name='mobile_personalization_signals',
    ),
    path('api/mobile/statement/', views_mobile.mobile_statement, name='mobile_statement'),
    path('api/mobile/assistant/chat/', views_mobile.mobile_assistant_chat, name='mobile_assistant_chat'),
    path(
        'api/mobile/assistant/diagnostics/',
        views_mobile.mobile_assistant_diagnostics,
        name='mobile_assistant_diagnostics',
    ),
    path('api/mobile/onboarding/self/', views_mobile.mobile_self_onboard, name='mobile_self_onboard'),
    path('metrics', views.metrics, name='metrics'),
    path('fx/exchange/', views.wallet_fx_exchange, name='wallet_fx_exchange'),
    path('backoffice/', views_backoffice.backoffice, name='backoffice'),
    path('backoffice/audit/export/', views_backoffice.backoffice_audit_export, name='backoffice_audit_export'),
    path('backoffice/rbac/', views_backoffice.rbac_management, name='rbac_management'),
    path('backoffice/fx/', views_backoffice.fx_management, name='fx_management'),
    path('backoffice/work-queue/', views_operations.ops_work_queue, name='ops_work_queue'),
    path('backoffice/approval-matrix/', views_operations.approval_matrix, name='approval_matrix'),
    path('backoffice/documents/', views_operations.documents_center, name='documents_center'),
    path('backoffice/settlements/', views_operations.settlement_operations, name='settlement_operations'),
    path('backoffice/reconciliation/', views_operations.reconciliation_workbench, name='reconciliation_workbench'),
    path('backoffice/reports/', views_operations.operations_reports, name='operations_reports'),
    path('backoffice/settings/', views_operations.operations_settings, name='operations_settings'),
    path('backoffice/policy-hub/', views_operations.policy_hub, name='policy_hub'),
    path('backoffice/operations/', views_operations.operations_center, name='operations_center'),
    path('backoffice/cases/<int:case_id>/', views_operations.case_detail, name='case_detail'),
    path('merchant/portal/', views_backoffice.merchant_portal, name='merchant_portal'),
    path('backoffice/wallets/', views_backoffice.wallet_management, name='wallet_management'),
    path('backoffice/accounting/', views_backoffice.accounting_dashboard, name='accounting_dashboard'),
    path(
        'backoffice/accounting/entries/<int:entry_id>/post/',
        views_backoffice.accounting_post_entry,
        name='accounting_post_entry',
    ),
    path('backoffice/treasury/', views_operations.treasury_dashboard, name='treasury_dashboard'),
    path(
        'backoffice/treasury/<int:request_id>/decision/',
        views_operations.treasury_decision,
        name='treasury_decision',
    ),
    path(
        'backoffice/approvals/<int:request_id>/decision/',
        views_operations.approval_decision,
        name='approval_decision',
    ),
    path('deposit/', views.deposit, name='deposit'),
    path('withdraw/', views.withdraw, name='withdraw'),
    path('transfer/', views.transfer, name='transfer'),
    path('register/', views_auth.register, name='register'),
    path('login/', views_auth.portal_login, name='login'),
    path('profile/', views_auth.profile, name='profile'),
    path('mobile/native-lab/', views_mobile.mobile_native_lab, name='mobile_native_lab'),
    path('api/playground/personas/', views_playground.mobile_playground_personas, name='mobile_playground_personas'),
    path(
        'api/playground/impersonation/',
        views_playground.mobile_playground_impersonation,
        name='mobile_playground_impersonation',
    ),
    path(
        'api/playground/policy-tariff/simulate/',
        views_playground.mobile_playground_policy_tariff_simulate,
        name='mobile_playground_policy_tariff_simulate',
    ),
    path(
        'api/playground/assistant/action/',
        views_playground.mobile_playground_assistant_action,
        name='mobile_playground_assistant_action',
    ),
    path(
        'api/playground/journey/run/',
        views_playground.mobile_playground_journey_run,
        name='mobile_playground_journey_run',
    ),
    path(
        'api/playground/feature-flags/preview/',
        views_playground.mobile_playground_feature_flags_preview,
        name='mobile_playground_feature_flags_preview',
    ),
    path('api/playground/abtest/', views_playground.mobile_playground_abtest, name='mobile_playground_abtest'),
    path(
        'api/playground/event/validate/',
        views_playground.mobile_playground_event_validate,
        name='mobile_playground_event_validate',
    ),
    path(
        'api/playground/risk/simulate/',
        views_playground.mobile_playground_risk_simulate,
        name='mobile_playground_risk_simulate',
    ),
    path(
        'api/playground/contracts/replay/',
        views_playground.mobile_playground_contract_replay,
        name='mobile_playground_contract_replay',
    ),
    path(
        'api/playground/release-gate/',
        views_playground.mobile_playground_release_gate,
        name='mobile_playground_release_gate',
    ),
    path('auth/keycloak/callback/', views_auth.keycloak_callback, name='keycloak_callback'),
    path('logout/', views_auth.portal_logout, name='logout'),
]
