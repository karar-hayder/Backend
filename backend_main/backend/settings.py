import os
import sys
from datetime import timedelta
from pathlib import Path
from tempfile import gettempdir

from mongoengine import connect

if not os.environ.get("SECRET_KEY", False):
    from dotenv import load_dotenv
    load_dotenv(".env.local")

BASE_DIR = Path(__file__).resolve().parent.parent

UPLOAD_STORAGE_DIR = os.environ.get("UPLOAD_STORAGE_DIR", os.path.join(BASE_DIR, "uploads_storage"))
try:
    os.makedirs(UPLOAD_STORAGE_DIR, exist_ok=True)
except OSError:
    UPLOAD_STORAGE_DIR = gettempdir()

SECRET_KEY = os.environ.get("SECRET_KEY", None)
DEBUG = os.environ.get("DEBUG", "False").lower() in ("true", "1", "t")

ALLOWED_HOSTS = (
    os.environ.get("ALLOWED_HOSTS", "").split(",")
    if os.environ.get("ALLOWED_HOSTS")
    else ["*"] if DEBUG else []
)
CORS_ALLOWED_ORIGINS = []
_cors_origins_env = os.environ.get("CORS_ALLOWED_ORIGINS")
_cors_allow_all_env = False
if _cors_origins_env:
    for origin in _cors_origins_env.split(","):
        origin = origin.strip()
        if not origin:
            continue
        if origin == "*":
            _cors_allow_all_env = True
            continue
        CORS_ALLOWED_ORIGINS.append(origin)


AI_HOST = os.environ.get("AI_HOST", "http://localhost:5001")

CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_ALL_ORIGINS = DEBUG or _cors_allow_all_env
CORS_ALLOW_HEADERS = [
    "Authorization",
    "Content-Type",
]

CORS_ALLOW_METHODS = [
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS",
]

REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")
CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", REDIS_URL)
CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", REDIS_URL)
CELERY_TASK_ACKS_LATE = True

if DEBUG or sys.platform.startswith("win"):
    CELERY_WORKER_POOL = "solo"
else:
    CELERY_WORKER_POOL = "prefork"
    CELERYD_CONCURRENCY = int(os.environ.get("CELERYD_CONCURRENCY", "2"))

CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_BEAT_SCHEDULE = {}

INSTALLED_APPS = [
    # Django main apps
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",

    # Third-party apps
    "corsheaders",
    "rest_framework",
    "rest_framework.authtoken",
    "rest_framework_simplejwt",
    "channels",

    # My apps
    "userss.apps.UserssConfig",
    "core.apps.CoreConfig",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "backend.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "backend.wsgi.application"

# The user model is correctly set to the custom user model in userss app
AUTH_USER_MODEL = "userss.CustomUser"

if DEBUG:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": os.path.join(BASE_DIR, "db.sqlite3"),
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.environ.get("DB_NAME", "hubits"),
            "USER": os.environ.get("DB_USER", "hubits"),
            "PASSWORD": os.environ.get("DB_PASSWORD", "hubits"),
            "HOST": os.environ.get("DB_HOST", "localhost"),
            "PORT": os.environ.get("DB_PORT", "5432"),
            # "TEST": {
            #     "NAME": os.environ.get("DB_TEST_NAME", "hubits_test"),
            # },
        }
    }


## Use .env
connect(db="hubits", host="mongodb://localhost:27017/hubits")

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(hours=4),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": False,
    "BLACKLIST_AFTER_ROTATION": True,
    "ALGORITHM": "HS256",
    "SIGNING_KEY": SECRET_KEY,
    "VERIFYING_KEY": None,
    "AUDIENCE": None,
    "ISSUER": None,
    "AUTH_HEADER_TYPES": ("Bearer",),
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
    "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.AccessToken",),
    "TOKEN_TYPE_CLAIM": "token_type",
    "JTI_CLAIM": "jti",
}

LOG_DIR = os.path.join(BASE_DIR, "logs")
try:
    os.makedirs(LOG_DIR, exist_ok=True)
except Exception:
    # Fallback to /tmp if logs directory cannot be created
    LOG_DIR = "/tmp"
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
    except Exception:
        LOG_DIR = None
if DEBUG:
    console_level = "DEBUG"
    apps_level = "DEBUG"
    main_level = "DEBUG"
else:
    console_level = "WARNING"
    apps_level = "INFO"
    main_level = "INFO"

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "[{asctime}] {levelname} [{process}:{thread}] [{name}] {message}",
            "style": "{",
            "datefmt": "%Y_%m_%d_%H_%M_%S",
        },
        "simple": {
            "format": "{levelname} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "level": console_level,
            "class": "logging.StreamHandler",
            "formatter": "simple",
        },
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": True,
        },
        "django.request": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
        "apps": {
            "handlers": ["console"],
            "level": apps_level,
            "propagate": True,
        },
        "__main__": {
            "handlers": ["console"],
            "level": main_level,
            "propagate": True,
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "WARNING",
    },
}

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

ASGI_APPLICATION = "backend.asgi.application"

CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [
                (
                    os.environ.get("REDIS_HOST", "redis"),
                    int(os.environ.get("REDIS_PORT", "6379")),
                )
            ],
        },
    },
}
