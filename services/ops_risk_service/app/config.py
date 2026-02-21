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
