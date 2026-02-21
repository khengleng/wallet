import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    service_name: str = os.getenv("SERVICE_NAME", "api-gateway-service")
    environment: str = os.getenv("ENVIRONMENT", "development")
    jwt_secret: str = os.getenv("JWT_SECRET", "")
    jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")
    jwt_audience: str = os.getenv("JWT_AUDIENCE", "wallet-api")
    jwt_issuer: str = os.getenv("JWT_ISSUER", "wallet-identity")
    ledger_base_url: str = os.getenv(
        "LEDGER_BASE_URL",
        "http://localhost:8081",
    )
    ledger_api_key: str = os.getenv("LEDGER_API_KEY", "")
    ledger_timeout_seconds: float = float(os.getenv("LEDGER_TIMEOUT_SECONDS", "10"))
    ledger_max_retries: int = int(os.getenv("LEDGER_MAX_RETRIES", "2"))
    ledger_retry_backoff_seconds: float = float(
        os.getenv("LEDGER_RETRY_BACKOFF_SECONDS", "0.2")
    )
    circuit_failure_threshold: int = int(
        os.getenv("LEDGER_CIRCUIT_FAILURE_THRESHOLD", "5")
    )
    circuit_reset_seconds: int = int(os.getenv("LEDGER_CIRCUIT_RESET_SECONDS", "30"))
    per_ip_limit: str = os.getenv("RATE_LIMIT_PER_IP", "120/minute")
    per_user_limit: str = os.getenv("RATE_LIMIT_PER_USER", "240/minute")

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"prod", "production"}


settings = Settings()

if settings.is_production:
    missing = [
        key
        for key, value in (
            ("JWT_SECRET", settings.jwt_secret),
            ("LEDGER_API_KEY", settings.ledger_api_key),
            ("LEDGER_BASE_URL", settings.ledger_base_url),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(f"Missing required production settings: {', '.join(missing)}")
