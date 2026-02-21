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


settings = Settings()
