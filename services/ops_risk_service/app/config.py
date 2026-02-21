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
    service_name: str = _env("SERVICE_NAME", "ops-risk-service")
    environment: str = _env("ENVIRONMENT", "development")
    database_isolation_mode: str = _env("DATABASE_ISOLATION_MODE", "compat").lower()
    database_url: str = _env(
        "OPS_RISK_DATABASE_URL",
        _env("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/ops_risk"),
    )
    broker_url: str = os.getenv("BROKER_URL", "amqp://guest:guest@localhost:5672/%2F")
    metrics_token: str = _env("METRICS_TOKEN", "")
    alert_webhook_token: str = _env("ALERT_WEBHOOK_TOKEN", "")
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
    onesignal_app_id: str = _env("ONESIGNAL_APP_ID", "").strip()
    onesignal_rest_api_key: str = _env("ONESIGNAL_REST_API_KEY", "").strip()
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
    if (
        settings.database_isolation_mode == "strict"
        and not _env("OPS_RISK_DATABASE_URL", "")
    ):
        raise RuntimeError(
            "OPS_RISK_DATABASE_URL must be set in production when DATABASE_ISOLATION_MODE=strict."
        )
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
