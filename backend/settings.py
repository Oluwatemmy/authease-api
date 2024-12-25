import environ, os
from pathlib import Path
from datetime import timedelta
from dotenv import load_dotenv

from corsheaders.defaults import default_headers

env = environ.Env(
    # set casting, default value
    DEBUG=(bool, False)
)

load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

environ.Env.read_env(BASE_DIR / '.env')

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = env("SECRET_KEY")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = env("DEBUG")

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # 3rd Party
    'rest_framework',
    'corsheaders',
    'rest_framework_simplejwt.token_blacklist',
    'rest_framework_swagger',
    'drf_yasg',
    # apps
    'accounts',
    'oauth',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'backend.wsgi.application'

CORS_ALLOWED_ORIGINS=[
    "http://localhost:3000",
    "http://localhost:5173"
]

CSRF_TRUSTED_ORGINS=[
    "http://localhost:3000",
    "http://localhost:5173"
]

# CORS_ALLOW_HEADERS = [
#     "accept",
#     "authorization",
#     "content-type",
#     "dnt",
#     "origin",
#     "user-agent",
#     "x-csrftoken",
#     "x-requested-with",
# ]

CORS_ALLOW_HEADERS = list(default_headers) + [
    'Authorization',
    'Content-Type',
]

# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    'NON_FIELD_ERRORS_KEY': 'error',
}

# On production disable Browseapi
if DEBUG == 'False':
    REST_FRAMEWORK["DEFAULT_RENDERER_CLASSES"] = (
        'rest_framework.renderers.JSONRenderer',
    )

AUTH_USER_MODEL="accounts.User"

# EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend' # Test locally on console
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend' # For production stage
# EMAIL_BACKEND='django.core.mail.bakends.locmem.EmailBackend' # For Testing in testcase

EMAIL_HOST = 'smtp.gmail.com' 
EMAIL_PORT = 465
EMAIL_USE_SSL = True
# EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.environ.get("EMAIL_HOST_USER") 
EMAIL_HOST_PASSWORD = os.environ.get("EMAIL_HOST_PASSWORD")
DEFAULT_FROM_EMAIL = 'authease00@gmail.com'

# EMAIL_HOST = 'sandbox.smtp.mailtrap.io'
# EMAIL_HOST_USER = env('EMAIL_HOST_USER')
# EMAIL_HOST_PASSWORD = env('EMAIL_HOST_PASSWORD')
# EMAIL_PORT = '2525'
# DEFAULT_FROM_EMAIL = 'oluwaseyitemitope456@gmail.com'
# EMAIL_USE_TLS = True


# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

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
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

SIMPLE_JWT = {
    # Token Lifetimes
    "ACCESS_TOKEN_LIFETIME": timedelta(hours=12),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),

    # Token Header Configuration
    "AUTH_HEADER_TYPES": ("Bearer",),               # Default is "Bearer"
    "AUTH_HEADER_NAME": "HTTP_AUTHORIZATION",       # Ensures proper header lookup

    # Rotation and Blacklisting
    "ROTATE_REFRESH_TOKENS": False,                  # Issue a new refresh token on each refresh
    "BLACKLIST_AFTER_ROTATION": True,               # Blacklist the old refresh token after rotation

    # Custom Claims and Validation
    "ALGORITHM": "HS256",                           # Ensure you're using a secure algorithm
    "SIGNING_KEY": SECRET_KEY,                      # Use Django's SECRET_KEY or a separate secure key
    "VERIFYING_KEY": None,                          # Public key for asymmetric algorithms like RS256
    "AUDIENCE": None,                               # Add audience claim if needed
    "ISSUER": None,                                 # Add issuer claim if needed

    # Sliding Tokens (Optional)
    "SLIDING_TOKEN_LIFETIME": timedelta(hours=12),  # For sliding sessions (if used)
    "SLIDING_TOKEN_REFRESH_LIFETIME": timedelta(days=1),

    # Miscellaneous
    "USER_ID_FIELD": "id",                          # Primary key field for user
    "USER_ID_CLAIM": "user_id",                     # Claim in the token for user ID
    "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.AccessToken",),
    "TOKEN_TYPE_CLAIM": "token_type",               # Claim for identifying token type
    "JTI_CLAIM": "jti",                             # JWT ID claim for unique identification
}

PASSWORD_RESET_TIMEOUT = 1800  # Set timeout to 30 minutes (1800 seconds)

GOOGLE_CLIENT_ID = env("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = env("GOOGLE_CLIENT_SECRET")

SOCIAL_AUTH_PASSWORD = os.environ.get("SOCIAL_AUTH_PASSWORD")

GITHUB_CLIENT_ID = env("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET")

SWAGGER_SETTINGS = {
    "ENABLED_METHODS": ["GET", "POST", "PUT", "PATCH", "DELETE"],
    "USE_SESSION_AUTH": True,
    "relative_paths": False,
    "DISPLAY_OPERATION_ID": False,
    "SECURITY_DEFINITIONS": {
        "Basic": {"type": "basic"},
        "Bearer": {"type": "apiKey", "name": "Authorization", "in": "header"},
    },
}