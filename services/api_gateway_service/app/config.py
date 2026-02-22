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
    service_name: str = _env("SERVICE_NAME", "api-gateway-service")
    environment: str = _env("ENVIRONMENT", "development")
    auth_mode: str = _env("AUTH_MODE", "local_jwt").strip().lower()
    jwt_secret: str = _env("JWT_SECRET", "")
    jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")
    jwt_audience: str = os.getenv("JWT_AUDIENCE", "wallet-api")
    jwt_issuer: str = os.getenv("JWT_ISSUER", "wallet-identity")
    identity_service_base_url: str = _env(
        "IDENTITY_SERVICE_BASE_URL", "http://localhost:8085"
    ).strip().rstrip("/")
    identity_service_api_key: str = _env("IDENTITY_SERVICE_API_KEY", "").strip()
    identity_service_timeout_seconds: float = float(
        os.getenv("IDENTITY_SERVICE_TIMEOUT_SECONDS", "3.0")
    )
    ledger_base_url: str = os.getenv(
        "LEDGER_BASE_URL",
        "http://localhost:8081",
    )
    internal_auth_mode: str = _env("INTERNAL_AUTH_MODE", "api_key").strip().lower()
    ledger_api_key: str = _env("LEDGER_API_KEY", "")
    internal_auth_shared_secret: str = _env("INTERNAL_AUTH_SHARED_SECRET", "")
    internal_auth_timestamp_skew_seconds: int = int(
        os.getenv("INTERNAL_AUTH_TIMESTAMP_SKEW_SECONDS", "90")
    )
    ledger_timeout_seconds: float = float(os.getenv("LEDGER_TIMEOUT_SECONDS", "10"))
    ledger_max_retries: int = int(os.getenv("LEDGER_MAX_RETRIES", "2"))
    ledger_retry_backoff_seconds: float = float(
        os.getenv("LEDGER_RETRY_BACKOFF_SECONDS", "0.2")
    )
    circuit_failure_threshold: int = int(
        os.getenv("LEDGER_CIRCUIT_FAILURE_THRESHOLD", "5")
    )
    circuit_reset_seconds: int = int(os.getenv("LEDGER_CIRCUIT_RESET_SECONDS", "30"))
    metrics_token: str = _env("METRICS_TOKEN", "")
    per_ip_limit: str = os.getenv("RATE_LIMIT_PER_IP", "120/minute")
    per_user_limit: str = os.getenv("RATE_LIMIT_PER_USER", "240/minute")
    read_per_ip_limit: str = os.getenv("RATE_LIMIT_READ_PER_IP", "300/minute")
    read_per_user_limit: str = os.getenv("RATE_LIMIT_READ_PER_USER", "600/minute")
    write_per_ip_limit: str = os.getenv("RATE_LIMIT_WRITE_PER_IP", "120/minute")
    write_per_user_limit: str = os.getenv("RATE_LIMIT_WRITE_PER_USER", "240/minute")
    critical_per_ip_limit: str = os.getenv("RATE_LIMIT_CRITICAL_PER_IP", "60/minute")
    critical_per_user_limit: str = os.getenv(
        "RATE_LIMIT_CRITICAL_PER_USER", "120/minute"
    )
    waf_blocked_ips: str = os.getenv("WAF_BLOCKED_IPS", "")
    waf_blocked_cidrs: str = os.getenv("WAF_BLOCKED_CIDRS", "")
    waf_blocked_user_agents: str = os.getenv("WAF_BLOCKED_USER_AGENTS", "")
    rate_limit_backend: str = os.getenv("RATE_LIMIT_BACKEND", "memory").strip().lower()
    redis_url: str = _env("REDIS_URL", "").strip()
    step_up_mfa_enabled: bool = os.getenv("STEP_UP_MFA_ENABLED", "true").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    step_up_mfa_critical_paths: str = os.getenv(
        "STEP_UP_MFA_CRITICAL_PATHS",
        "/v1/transactions/withdraw,/v1/transactions/transfer",
    )
    step_up_mfa_amr_values: str = os.getenv(
        "STEP_UP_MFA_AMR_VALUES",
        "mfa,otp,totp,webauthn",
    )
    step_up_mfa_acr_values: str = os.getenv(
        "STEP_UP_MFA_ACR_VALUES",
        "2,urn:mace:incommon:iap:silver",
    )

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"prod", "production"}


settings = Settings()

if settings.is_production:
    missing = []
    if settings.auth_mode == "keycloak_oidc":
        missing.extend(
            [
                key
                for key, value in (
                    ("IDENTITY_SERVICE_BASE_URL", settings.identity_service_base_url),
                    ("IDENTITY_SERVICE_API_KEY", settings.identity_service_api_key),
                )
                if not value
            ]
        )
    else:
        missing.extend(
            [
                key
                for key, value in (
                    ("JWT_SECRET", settings.jwt_secret),
                    ("JWT_ISSUER", settings.jwt_issuer),
                    ("JWT_AUDIENCE", settings.jwt_audience),
                )
                if not value
            ]
        )
    if settings.internal_auth_mode == "hmac":
        missing.extend(
            [
                key
                for key, value in (
                    ("INTERNAL_AUTH_SHARED_SECRET", settings.internal_auth_shared_secret),
                    ("LEDGER_BASE_URL", settings.ledger_base_url),
                    ("METRICS_TOKEN", settings.metrics_token),
                )
                if not value
            ]
        )
    else:
        missing.extend(
            [
                key
                for key, value in (
                    ("LEDGER_API_KEY", settings.ledger_api_key),
                    ("LEDGER_BASE_URL", settings.ledger_base_url),
                    ("METRICS_TOKEN", settings.metrics_token),
                )
                if not value
            ]
        )
    if missing:
        raise RuntimeError(f"Missing required production settings: {', '.join(missing)}")
