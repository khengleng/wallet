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
    service_name: str = _env("SERVICE_NAME", "audit-export-worker")
    environment: str = _env("ENVIRONMENT", "development")
    database_isolation_mode: str = _env("DATABASE_ISOLATION_MODE", "compat").lower()
    database_url: str = _env(
        "AUDIT_EXPORT_DATABASE_URL",
        _env(
            "BACKOFFICE_DATABASE_URL",
            _env("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/railway"),
        ),
    )
    siem_webhook_url: str = _env("SIEM_WEBHOOK_URL", "").strip()
    siem_signing_secret: str = _env("SIEM_SIGNING_SECRET", "").strip()
    siem_timeout_seconds: float = float(os.getenv("SIEM_TIMEOUT_SECONDS", "10"))
    export_batch_size: int = int(os.getenv("EXPORT_BATCH_SIZE", "200"))
    export_replay_batch_size: int = int(os.getenv("EXPORT_REPLAY_BATCH_SIZE", "100"))
    export_poll_interval_seconds: float = float(
        os.getenv("EXPORT_POLL_INTERVAL_SECONDS", "2")
    )
    export_max_attempts: int = int(os.getenv("EXPORT_MAX_ATTEMPTS", "20"))
    export_retry_base_seconds: int = int(os.getenv("EXPORT_RETRY_BASE_SECONDS", "2"))
    metrics_token: str = _env("METRICS_TOKEN", "")

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"prod", "production"}


settings = Settings()

if settings.is_production:
    if (
        settings.database_isolation_mode == "strict"
        and not _env("AUDIT_EXPORT_DATABASE_URL", "")
        and not _env("BACKOFFICE_DATABASE_URL", "")
    ):
        raise RuntimeError(
            "AUDIT_EXPORT_DATABASE_URL or BACKOFFICE_DATABASE_URL must be set in production "
            "when DATABASE_ISOLATION_MODE=strict."
        )
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
