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
