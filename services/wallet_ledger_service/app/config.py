import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    service_name: str = os.getenv("SERVICE_NAME", "wallet-ledger-service")
    environment: str = os.getenv("ENVIRONMENT", "development")
    database_url: str = os.getenv(
        "DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/wallet_ledger"
    )
    default_currency: str = os.getenv("DEFAULT_CURRENCY", "USD")
    service_api_key: str = os.getenv("SERVICE_API_KEY", "")
    metrics_token: str = os.getenv("METRICS_TOKEN", "")
    broker_url: str = os.getenv("BROKER_URL", "amqp://guest:guest@localhost:5672/%2F")
    outbox_exchange: str = os.getenv("OUTBOX_EXCHANGE", "wallet.events")
    outbox_exchange_type: str = os.getenv("OUTBOX_EXCHANGE_TYPE", "topic")
    outbox_routing_key_prefix: str = os.getenv("OUTBOX_ROUTING_KEY_PREFIX", "ledger")
    outbox_poll_interval_seconds: float = float(
        os.getenv("OUTBOX_POLL_INTERVAL_SECONDS", "1.0")
    )
    outbox_batch_size: int = int(os.getenv("OUTBOX_BATCH_SIZE", "100"))
    outbox_max_attempts: int = int(os.getenv("OUTBOX_MAX_ATTEMPTS", "20"))
    outbox_retry_base_seconds: int = int(os.getenv("OUTBOX_RETRY_BASE_SECONDS", "2"))
    outbox_processing_timeout_seconds: int = int(
        os.getenv("OUTBOX_PROCESSING_TIMEOUT_SECONDS", "60")
    )

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"prod", "production"}


settings = Settings()

if settings.is_production and not settings.service_api_key:
    raise RuntimeError("SERVICE_API_KEY must be set in production.")
