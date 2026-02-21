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

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"prod", "production"}


settings = Settings()

if settings.is_production and not settings.service_api_key:
    raise RuntimeError("SERVICE_API_KEY must be set in production.")
