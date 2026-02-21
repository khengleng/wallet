import os
from dataclasses import dataclass
from urllib import error as urlerror
from urllib import request as urlrequest
import json


def _env(key: str, default: str = "") -> str:
    value = os.getenv(key, "").strip()
    if value:
        return value
    file_path = os.getenv(f"{key}_FILE", "").strip()
    if file_path:
        try:
            with open(file_path, "r", encoding="utf-8") as secret_file:
                file_value = secret_file.read().strip()
            if file_value:
                return file_value
        except OSError:
            pass
    vault_addr = os.getenv("VAULT_ADDR", "").strip().rstrip("/")
    vault_token = os.getenv("VAULT_TOKEN", "").strip()
    vault_path = os.getenv(f"{key}_VAULT_PATH", "").strip().strip("/")
    if not (vault_addr and vault_token and vault_path):
        return default
    vault_field = os.getenv(f"{key}_VAULT_FIELD", key)
    headers = {"X-Vault-Token": vault_token}
    namespace = os.getenv("VAULT_NAMESPACE", "").strip()
    if namespace:
        headers["X-Vault-Namespace"] = namespace
    req = urlrequest.Request(f"{vault_addr}/v1/{vault_path}", headers=headers)
    try:
        with urlrequest.urlopen(req, timeout=float(os.getenv("VAULT_TIMEOUT_SECONDS", "3"))) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        return str(payload.get("data", {}).get("data", {}).get(vault_field, default)).strip()
    except (urlerror.URLError, TimeoutError, ValueError, json.JSONDecodeError):
        return default


@dataclass(frozen=True)
class Settings:
    service_name: str = _env("SERVICE_NAME", "wallet-ledger-service")
    environment: str = _env("ENVIRONMENT", "development")
    database_isolation_mode: str = _env("DATABASE_ISOLATION_MODE", "compat").lower()
    database_url: str = _env(
        "LEDGER_DATABASE_URL",
        _env("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/wallet_ledger"),
    )
    default_currency: str = _env("DEFAULT_CURRENCY", "USD")
    internal_auth_mode: str = _env("INTERNAL_AUTH_MODE", "api_key").strip().lower()
    service_api_key: str = _env("SERVICE_API_KEY", "")
    internal_auth_shared_secret: str = _env("INTERNAL_AUTH_SHARED_SECRET", "")
    internal_auth_timestamp_skew_seconds: int = int(
        os.getenv("INTERNAL_AUTH_TIMESTAMP_SKEW_SECONDS", "90")
    )
    internal_auth_nonce_ttl_seconds: int = int(
        os.getenv("INTERNAL_AUTH_NONCE_TTL_SECONDS", "300")
    )
    metrics_token: str = _env("METRICS_TOKEN", "")
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

if settings.is_production:
    if (
        settings.database_isolation_mode == "strict"
        and not _env("LEDGER_DATABASE_URL", "")
    ):
        raise RuntimeError(
            "LEDGER_DATABASE_URL must be set in production when DATABASE_ISOLATION_MODE=strict."
        )
    missing = [
        key
        for key, value in (
            ("METRICS_TOKEN", settings.metrics_token),
        )
        if not value
    ]
    if settings.internal_auth_mode == "hmac":
        if not settings.internal_auth_shared_secret:
            missing.append("INTERNAL_AUTH_SHARED_SECRET")
    elif not settings.service_api_key:
        missing.append("SERVICE_API_KEY")
    if missing:
        raise RuntimeError(
            f"Missing required production settings: {', '.join(missing)}"
        )
