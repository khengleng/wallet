import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    service_name: str = os.getenv("SERVICE_NAME", "ops-risk-service")
    environment: str = os.getenv("ENVIRONMENT", "development")
    database_url: str = os.getenv(
        "DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/ops_risk"
    )
    broker_url: str = os.getenv("BROKER_URL", "amqp://guest:guest@localhost:5672/%2F")
    metrics_token: str = os.getenv("METRICS_TOKEN", "")
    alert_webhook_token: str = os.getenv("ALERT_WEBHOOK_TOKEN", "")
    exchange_name: str = os.getenv("EVENT_EXCHANGE_NAME", "wallet.events")
    exchange_type: str = os.getenv("EVENT_EXCHANGE_TYPE", "topic")
    queue_name: str = os.getenv("EVENT_QUEUE_NAME", "ops_risk_events")
    queue_routing_key: str = os.getenv("EVENT_ROUTING_KEY", "ledger.#")
    consumer_prefetch: int = int(os.getenv("EVENT_CONSUMER_PREFETCH", "50"))
    risk_high_value_threshold: str = os.getenv("RISK_HIGH_VALUE_THRESHOLD", "10000")
    onesignal_enabled: bool = os.getenv("ONESIGNAL_ENABLED", "false").lower() == "true"
    onesignal_api_base_url: str = os.getenv(
        "ONESIGNAL_API_BASE_URL", "https://api.onesignal.com"
    ).rstrip("/")
    onesignal_app_id: str = os.getenv("ONESIGNAL_APP_ID", "").strip()
    onesignal_rest_api_key: str = os.getenv("ONESIGNAL_REST_API_KEY", "").strip()
    onesignal_timeout_seconds: float = float(
        os.getenv("ONESIGNAL_TIMEOUT_SECONDS", "5")
    )
    onesignal_target_segments: str = os.getenv(
        "ONESIGNAL_TARGET_SEGMENTS", "Subscribed Users"
    )

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"prod", "production"}


settings = Settings()

if settings.is_production:
    missing = [
        key
        for key, value in (
            ("METRICS_TOKEN", settings.metrics_token),
            ("ALERT_WEBHOOK_TOKEN", settings.alert_webhook_token),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(f"Missing required production settings: {', '.join(missing)}")
    if settings.onesignal_enabled:
        onesignal_missing = [
            key
            for key, value in (
                ("ONESIGNAL_APP_ID", settings.onesignal_app_id),
                ("ONESIGNAL_REST_API_KEY", settings.onesignal_rest_api_key),
            )
            if not value
        ]
        if onesignal_missing:
            raise RuntimeError(
                f"Missing required OneSignal settings: {', '.join(onesignal_missing)}"
            )
