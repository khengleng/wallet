"""
Django settings for demo_project_app project.
"""

import os
from pathlib import Path
import json
from urllib import error as urlerror
from urllib import request as urlrequest

import dj_database_url
from django.core.exceptions import ImproperlyConfigured

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


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


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/6.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = _env("SECRET_KEY")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = _env("DEBUG", "False").lower() == "true"
IS_PRODUCTION = _env("ENVIRONMENT", "").lower() in {
    "prod",
    "production",
} or not DEBUG

import sys

IS_BUILD = "collectstatic" in sys.argv

if not SECRET_KEY and IS_PRODUCTION and not IS_BUILD:
    raise ImproperlyConfigured("SECRET_KEY must be set in production.")

if not SECRET_KEY:
    SECRET_KEY = "dev-only-secret-key"

ALLOWED_HOSTS = [
    host.strip()
    for host in os.getenv("ALLOWED_HOSTS", "*").split(",")
    if host.strip()
]

if IS_PRODUCTION and (not ALLOWED_HOSTS or ALLOWED_HOSTS == ["*"]) and not IS_BUILD:
    raise ImproperlyConfigured(
        "ALLOWED_HOSTS must be explicitly set in production and cannot be '*'."
    )


# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "dj_wallet",
    "wallets_demo",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "wallets_demo.middleware.KeycloakSessionGuardMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "demo_project_app.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "demo_project_app.wsgi.application"


# Database
# https://docs.djangoproject.com/en/6.0/ref/settings/#databases

DATABASE_URL = _env("DATABASE_URL")
BACKOFFICE_DATABASE_URL = _env("BACKOFFICE_DATABASE_URL", DATABASE_URL)
DATABASE_ISOLATION_MODE = _env("DATABASE_ISOLATION_MODE", "compat").lower()
if IS_PRODUCTION and DATABASE_ISOLATION_MODE == "strict" and not BACKOFFICE_DATABASE_URL and not IS_BUILD:
    raise ImproperlyConfigured(
        "BACKOFFICE_DATABASE_URL must be set in production when DATABASE_ISOLATION_MODE=strict."
    )

if BACKOFFICE_DATABASE_URL:
    DATABASES = {
        "default": dj_database_url.parse(
            BACKOFFICE_DATABASE_URL,
            conn_max_age=600,
            ssl_require=True,
        )
    }
    # Works better behind connection poolers (e.g. PgBouncer).
    DATABASES["default"]["CONN_HEALTH_CHECKS"] = True
    DATABASES["default"]["DISABLE_SERVER_SIDE_CURSORS"] = True
else:
    if IS_PRODUCTION and not IS_BUILD:
        raise ImproperlyConfigured(
            "DATABASE_URL must be set in production (PostgreSQL required)."
        )
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }


# Password validation
# https://docs.djangoproject.com/en/6.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/6.0/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/6.0/howto/static-files/

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

AUTH_USER_MODEL = "wallets_demo.User"

dj_wallet = {
    "MATH_SCALE": 2,
    "DEFAULT_CURRENCY": "USD",
}
PLATFORM_BASE_CURRENCY = os.getenv("PLATFORM_BASE_CURRENCY", "USD").upper()
SUPPORTED_CURRENCIES = [
    c.strip().upper()
    for c in os.getenv("SUPPORTED_CURRENCIES", "USD,EUR,SGD,GBP").split(",")
    if c.strip()
]
FX_PROVIDER = os.getenv("FX_PROVIDER", "frankfurter").strip().lower()
FX_PROVIDER_TIMEOUT_SECONDS = int(os.getenv("FX_PROVIDER_TIMEOUT_SECONDS", "10"))
FX_PROVIDER_BASE_URL = os.getenv(
    "FX_PROVIDER_BASE_URL", "https://api.frankfurter.app"
).strip()
FX_PROVIDER_API_KEY = _env("FX_PROVIDER_API_KEY", "").strip()
FX_PROVIDER_FALLBACK = os.getenv("FX_PROVIDER_FALLBACK", "open_er_api").strip().lower()
REDIS_URL = os.getenv("REDIS_URL", "").strip()
FX_RATE_CACHE_TTL_SECONDS = int(os.getenv("FX_RATE_CACHE_TTL_SECONDS", "60"))
METRICS_TOKEN = _env("METRICS_TOKEN", "").strip()
AUTH_MODE = os.getenv("AUTH_MODE", "local").strip().lower()
KEYCLOAK_BASE_URL = os.getenv("KEYCLOAK_BASE_URL", "").strip().rstrip("/")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "").strip()
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "").strip()
KEYCLOAK_CLIENT_SECRET = _env("KEYCLOAK_CLIENT_SECRET", "").strip()
KEYCLOAK_REDIRECT_URI = os.getenv("KEYCLOAK_REDIRECT_URI", "").strip()
KEYCLOAK_POST_LOGOUT_REDIRECT_URI = os.getenv("KEYCLOAK_POST_LOGOUT_REDIRECT_URI", "").strip()
KEYCLOAK_SCOPES = os.getenv("KEYCLOAK_SCOPES", "openid profile email").strip()
KEYCLOAK_INTROSPECTION_TIMEOUT_SECONDS = float(
    os.getenv("KEYCLOAK_INTROSPECTION_TIMEOUT_SECONDS", "3.0")
)
KEYCLOAK_SESSION_CHECK_INTERVAL_SECONDS = int(
    os.getenv("KEYCLOAK_SESSION_CHECK_INTERVAL_SECONDS", "120")
)
IDENTITY_SERVICE_BASE_URL = _env("IDENTITY_SERVICE_BASE_URL", "").strip().rstrip("/")
IDENTITY_SERVICE_API_KEY = _env("IDENTITY_SERVICE_API_KEY", "").strip()
IDENTITY_SERVICE_TIMEOUT_SECONDS = float(
    os.getenv("IDENTITY_SERVICE_TIMEOUT_SECONDS", "5.0")
)


def _parse_keycloak_role_group_map() -> dict[str, str]:
    raw_value = os.getenv(
        "KEYCLOAK_ROLE_GROUP_MAP",
        "super_admin:super_admin,admin:admin,finance:finance,treasury:treasury,"
        "customer_service:customer_service,risk:risk,operation:operation,sales:sales",
    )
    result: dict[str, str] = {}
    for entry in raw_value.split(","):
        pair = entry.strip()
        if not pair or ":" not in pair:
            continue
        left, right = pair.split(":", 1)
        key = left.strip().lower().replace(" ", "_").replace("-", "_")
        value = right.strip().lower().replace(" ", "_").replace("-", "_")
        if key and value:
            result[key] = value
    return result


KEYCLOAK_ROLE_GROUP_MAP = _parse_keycloak_role_group_map()
AUDIT_EXPORT_HMAC_SECRET = _env("AUDIT_EXPORT_HMAC_SECRET", SECRET_KEY or "").strip()
AUDIT_EXPORT_MAX_DAYS = int(os.getenv("AUDIT_EXPORT_MAX_DAYS", "90"))
CLEVERTAP_ENABLED = os.getenv("CLEVERTAP_ENABLED", "false").lower() == "true"
CLEVERTAP_ACCOUNT_ID = _env("CLEVERTAP_ACCOUNT_ID", "").strip()
CLEVERTAP_PASSCODE = _env("CLEVERTAP_PASSCODE", "").strip()
CLEVERTAP_REGION = os.getenv("CLEVERTAP_REGION", "us1").strip()
CLEVERTAP_EVENT_ENDPOINT = os.getenv("CLEVERTAP_EVENT_ENDPOINT", "").strip()
CLEVERTAP_TIMEOUT_SECONDS = float(os.getenv("CLEVERTAP_TIMEOUT_SECONDS", "5"))

if REDIS_URL:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": REDIS_URL,
        }
    }
else:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "wallet-default",
        }
    }

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "dashboard"
LOGOUT_REDIRECT_URL = "login"
SESSION_COOKIE_AGE = int(os.getenv("SESSION_COOKIE_AGE_SECONDS", "43200"))
SESSION_SAVE_EVERY_REQUEST = True
SESSION_ENGINE = os.getenv(
    "SESSION_ENGINE",
    "django.contrib.sessions.backends.cache" if REDIS_URL else "django.contrib.sessions.backends.db",
)
SESSION_CACHE_ALIAS = "default"

CSRF_TRUSTED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("CSRF_TRUSTED_ORIGINS", "").split(",")
    if origin.strip()
]

LOGIN_LOCKOUT_WINDOW_MINUTES = int(os.getenv("LOGIN_LOCKOUT_WINDOW_MINUTES", "15"))
LOGIN_LOCKOUT_THRESHOLD = int(os.getenv("LOGIN_LOCKOUT_THRESHOLD", "5"))
LOGIN_LOCKOUT_DURATION_MINUTES = int(
    os.getenv("LOGIN_LOCKOUT_DURATION_MINUTES", "30")
)
LOGIN_LOCKOUT_USE_CACHE = os.getenv("LOGIN_LOCKOUT_USE_CACHE", "True").lower() == "true"

if IS_PRODUCTION and not CSRF_TRUSTED_ORIGINS and not IS_BUILD:
    raise ImproperlyConfigured(
        "CSRF_TRUSTED_ORIGINS must be set in production."
    )

if AUTH_MODE == "keycloak_oidc":
    missing_keycloak = [
        key
        for key, value in (
            ("KEYCLOAK_CLIENT_ID", KEYCLOAK_CLIENT_ID),
            ("KEYCLOAK_REDIRECT_URI", KEYCLOAK_REDIRECT_URI),
            ("IDENTITY_SERVICE_BASE_URL", IDENTITY_SERVICE_BASE_URL),
            ("IDENTITY_SERVICE_API_KEY", IDENTITY_SERVICE_API_KEY),
        )
        if not value
    ]
    if missing_keycloak and IS_PRODUCTION and not IS_BUILD:
        raise ImproperlyConfigured(
            "Missing required Keycloak settings: " + ", ".join(missing_keycloak)
        )

if not DEBUG:
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    CSRF_COOKIE_HTTPONLY = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = "DENY"
    SECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"
