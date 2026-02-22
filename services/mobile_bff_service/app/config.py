import json
import os
from dataclasses import dataclass
from urllib import error as urlerror
from urllib import request as urlrequest


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
    service_name: str = _env("SERVICE_NAME", "mobile-bff-service")
    environment: str = _env("ENVIRONMENT", "development")
    service_api_key: str = _env("SERVICE_API_KEY", "")
    metrics_token: str = _env("METRICS_TOKEN", "")
    identity_service_base_url: str = _env(
        "IDENTITY_SERVICE_BASE_URL",
        "http://localhost:8085",
    ).strip().rstrip("/")
    identity_service_api_key: str = _env("IDENTITY_SERVICE_API_KEY", "")
    identity_service_timeout_seconds: float = float(
        os.getenv("IDENTITY_SERVICE_TIMEOUT_SECONDS", "3.0")
    )
    web_service_base_url: str = _env(
        "WEB_SERVICE_BASE_URL",
        "http://localhost:8000",
    ).strip().rstrip("/")
    web_service_timeout_seconds: float = float(os.getenv("WEB_SERVICE_TIMEOUT_SECONDS", "8.0"))
    mobile_rate_limit_per_token: str = os.getenv("MOBILE_RATE_LIMIT_PER_TOKEN", "240/minute")
    mobile_rate_limit_per_ip: str = os.getenv("MOBILE_RATE_LIMIT_PER_IP", "180/minute")

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"prod", "production"}


settings = Settings()

if settings.is_production:
    missing = [
        key
        for key, value in (
            ("SERVICE_API_KEY", settings.service_api_key),
            ("METRICS_TOKEN", settings.metrics_token),
            ("IDENTITY_SERVICE_BASE_URL", settings.identity_service_base_url),
            ("IDENTITY_SERVICE_API_KEY", settings.identity_service_api_key),
            ("WEB_SERVICE_BASE_URL", settings.web_service_base_url),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(f"Missing required production settings: {', '.join(missing)}")
