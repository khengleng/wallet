import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    service_name: str = os.getenv("SERVICE_NAME", "audit-export-worker")
    environment: str = os.getenv("ENVIRONMENT", "development")
    database_url: str = os.getenv(
        "DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/railway"
    )
    siem_webhook_url: str = os.getenv("SIEM_WEBHOOK_URL", "").strip()
    siem_signing_secret: str = os.getenv("SIEM_SIGNING_SECRET", "").strip()
    siem_timeout_seconds: float = float(os.getenv("SIEM_TIMEOUT_SECONDS", "10"))
    export_batch_size: int = int(os.getenv("EXPORT_BATCH_SIZE", "200"))
    export_replay_batch_size: int = int(os.getenv("EXPORT_REPLAY_BATCH_SIZE", "100"))
    export_poll_interval_seconds: float = float(
        os.getenv("EXPORT_POLL_INTERVAL_SECONDS", "2")
    )
    export_max_attempts: int = int(os.getenv("EXPORT_MAX_ATTEMPTS", "20"))
    export_retry_base_seconds: int = int(os.getenv("EXPORT_RETRY_BASE_SECONDS", "2"))
    metrics_token: str = os.getenv("METRICS_TOKEN", "")

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"prod", "production"}


settings = Settings()

if settings.is_production:
    missing = [
        key
        for key, value in (
            ("DATABASE_URL", settings.database_url),
            ("SIEM_WEBHOOK_URL", settings.siem_webhook_url),
            ("SIEM_SIGNING_SECRET", settings.siem_signing_secret),
            ("METRICS_TOKEN", settings.metrics_token),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(f"Missing required production settings: {', '.join(missing)}")
