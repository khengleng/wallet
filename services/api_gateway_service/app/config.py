import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    service_name: str = os.getenv("SERVICE_NAME", "api-gateway-service")
    environment: str = os.getenv("ENVIRONMENT", "development")
    auth_mode: str = os.getenv("AUTH_MODE", "local_jwt").strip().lower()
    jwt_secret: str = os.getenv("JWT_SECRET", "")
    jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")
    jwt_audience: str = os.getenv("JWT_AUDIENCE", "wallet-api")
    jwt_issuer: str = os.getenv("JWT_ISSUER", "wallet-identity")
    keycloak_base_url: str = os.getenv("KEYCLOAK_BASE_URL", "").strip().rstrip("/")
    keycloak_realm: str = os.getenv("KEYCLOAK_REALM", "").strip()
    keycloak_client_id: str = os.getenv("KEYCLOAK_CLIENT_ID", "").strip()
    keycloak_client_secret: str = os.getenv("KEYCLOAK_CLIENT_SECRET", "").strip()
    keycloak_introspection_timeout_seconds: float = float(
        os.getenv("KEYCLOAK_INTROSPECTION_TIMEOUT_SECONDS", "2.0")
    )
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
    metrics_token: str = os.getenv("METRICS_TOKEN", "")
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
                    ("KEYCLOAK_BASE_URL", settings.keycloak_base_url),
                    ("KEYCLOAK_REALM", settings.keycloak_realm),
                    ("KEYCLOAK_CLIENT_ID", settings.keycloak_client_id),
                    ("KEYCLOAK_CLIENT_SECRET", settings.keycloak_client_secret),
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
