from django.urls import path

from . import views_mobile
from . import views_playground

app_name = "mobile_portal"

urlpatterns = [
    path("", views_mobile.mobile_native_lab, name="home"),
    path("api/mobile/bootstrap/", views_mobile.mobile_bootstrap, name="mobile_bootstrap"),
    path("api/mobile/profile/", views_mobile.mobile_profile, name="mobile_profile"),
    path(
        "api/mobile/personalization/",
        views_mobile.mobile_personalization,
        name="mobile_personalization",
    ),
    path(
        "api/mobile/personalization/signals/",
        views_mobile.mobile_personalization_signals,
        name="mobile_personalization_signals",
    ),
    path("api/mobile/statement/", views_mobile.mobile_statement, name="mobile_statement"),
    path("api/mobile/assistant/chat/", views_mobile.mobile_assistant_chat, name="mobile_assistant_chat"),
    path(
        "api/mobile/assistant/diagnostics/",
        views_mobile.mobile_assistant_diagnostics,
        name="mobile_assistant_diagnostics",
    ),
    path("api/mobile/onboarding/self/", views_mobile.mobile_self_onboard, name="mobile_self_onboard"),
    path("api/playground/personas/", views_playground.mobile_playground_personas, name="playground_personas"),
    path(
        "api/playground/impersonation/",
        views_playground.mobile_playground_impersonation,
        name="playground_impersonation",
    ),
    path(
        "api/playground/policy-tariff/simulate/",
        views_playground.mobile_playground_policy_tariff_simulate,
        name="playground_policy_tariff_simulate",
    ),
    path(
        "api/playground/assistant/action/",
        views_playground.mobile_playground_assistant_action,
        name="playground_assistant_action",
    ),
    path(
        "api/playground/journey/run/",
        views_playground.mobile_playground_journey_run,
        name="playground_journey_run",
    ),
    path(
        "api/playground/feature-flags/preview/",
        views_playground.mobile_playground_feature_flags_preview,
        name="playground_feature_flags_preview",
    ),
    path("api/playground/abtest/", views_playground.mobile_playground_abtest, name="playground_abtest"),
    path(
        "api/playground/event/validate/",
        views_playground.mobile_playground_event_validate,
        name="playground_event_validate",
    ),
    path(
        "api/playground/risk/simulate/",
        views_playground.mobile_playground_risk_simulate,
        name="playground_risk_simulate",
    ),
    path(
        "api/playground/contracts/replay/",
        views_playground.mobile_playground_contract_replay,
        name="playground_contract_replay",
    ),
    path(
        "api/playground/release-gate/",
        views_playground.mobile_playground_release_gate,
        name="playground_release_gate",
    ),
]
