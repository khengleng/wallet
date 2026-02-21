"""
Django settings for demo_project_app project.
"""

import os
from pathlib import Path

import dj_database_url
from django.core.exceptions import ImproperlyConfigured

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/6.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv("SECRET_KEY")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv("DEBUG", "False").lower() == "true"
IS_PRODUCTION = os.getenv("ENVIRONMENT", "").lower() in {
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

DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL:
    DATABASES = {
        "default": dj_database_url.parse(
            DATABASE_URL,
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
FX_PROVIDER_API_KEY = os.getenv("FX_PROVIDER_API_KEY", "").strip()

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "dashboard"
LOGOUT_REDIRECT_URL = "login"
SESSION_COOKIE_AGE = int(os.getenv("SESSION_COOKIE_AGE_SECONDS", "43200"))
SESSION_SAVE_EVERY_REQUEST = True

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

if IS_PRODUCTION and not CSRF_TRUSTED_ORIGINS and not IS_BUILD:
    raise ImproperlyConfigured(
        "CSRF_TRUSTED_ORIGINS must be set in production."
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
