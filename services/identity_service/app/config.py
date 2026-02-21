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
    service_name: str = _env("SERVICE_NAME", "identity-service")
    environment: str = _env("ENVIRONMENT", "development")
    database_isolation_mode: str = _env("DATABASE_ISOLATION_MODE", "compat").lower()
    database_url: str = _env(
        "IDENTITY_DATABASE_URL",
        _env("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/identity"),
    )
    service_api_key: str = _env("SERVICE_API_KEY", "")
    metrics_token: str = _env("METRICS_TOKEN", "")
    keycloak_base_url: str = _env("KEYCLOAK_BASE_URL", "").strip().rstrip("/")
    keycloak_realm: str = _env("KEYCLOAK_REALM", "").strip()
    keycloak_client_id: str = _env("KEYCLOAK_CLIENT_ID", "").strip()
    keycloak_client_secret: str = _env("KEYCLOAK_CLIENT_SECRET", "").strip()
    keycloak_scopes: str = _env("KEYCLOAK_SCOPES", "openid profile email").strip()
    keycloak_timeout_seconds: float = float(os.getenv("KEYCLOAK_TIMEOUT_SECONDS", "5"))
    introspection_cache_ttl_seconds: int = int(
        os.getenv("INTROSPECTION_CACHE_TTL_SECONDS", "30")
    )
    session_idle_timeout_seconds: int = int(
        os.getenv("SESSION_IDLE_TIMEOUT_SECONDS", "43200")
    )

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
            ("KEYCLOAK_BASE_URL", settings.keycloak_base_url),
            ("KEYCLOAK_REALM", settings.keycloak_realm),
            ("KEYCLOAK_CLIENT_ID", settings.keycloak_client_id),
            ("KEYCLOAK_CLIENT_SECRET", settings.keycloak_client_secret),
        )
        if not value
    ]
    if settings.database_isolation_mode == "strict" and not _env("IDENTITY_DATABASE_URL", ""):
        missing.append("IDENTITY_DATABASE_URL")
    if missing:
        raise RuntimeError(f"Missing required production settings: {', '.join(missing)}")
