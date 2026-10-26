"""Central configuration (12-factor: everything overridable via env / .env)."""
from functools import lru_cache
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    APP_NAME: str = "TrustShare"
    ENV: str = "development"
    FRONTEND_URL: str = "http://localhost:3000"
    BACKEND_URL: str = "http://localhost:8000"
    CORS_ORIGINS: str = "http://localhost:3000"

    # --- databases -------------------------------------------------------
    DATABASE_URL: str = f"sqlite:///{BASE_DIR / 'data' / 'trustshare.db'}"
    MONGO_URL: str = ""          # e.g. mongodb://localhost:27017 (empty => SQL audit fallback)
    MONGO_DB: str = "trustshare"
    REDIS_URL: str = ""          # e.g. redis://localhost:6379/0 (empty => in-memory fallback)

    # --- auth ------------------------------------------------------------
    JWT_SECRET: str = "change-me-in-production-please-use-64-random-chars"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_MINUTES: int = 15
    REFRESH_TOKEN_DAYS: int = 7
    MFA_TOKEN_MINUTES: int = 5
    RESET_TOKEN_MINUTES: int = 30
    MAX_FAILED_LOGINS: int = 5
    LOCKOUT_MINUTES: int = 15
    ADMIN_EMAIL: str = ""        # this email always registers as admin; first user is admin too

    # --- OAuth2 (optional) ----------------------------------------------
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""

    # --- encryption / storage -------------------------------------------
    MASTER_KEYS: str = ""        # "1:<base64-32-bytes>,2:<base64-32-bytes>"; empty => dev key file
    ACTIVE_KEY_VERSION: int = 0  # 0 => highest available
    STORAGE_BACKEND: str = "local"   # local | s3 | azure
    LOCAL_STORAGE_DIR: str = str(BASE_DIR / "data" / "encrypted_storage")
    S3_BUCKET: str = ""
    S3_REGION: str = "us-east-1"
    S3_ENDPOINT_URL: str = ""    # for MinIO/localstack
    AZURE_CONNECTION_STRING: str = ""
    AZURE_CONTAINER: str = "trustshare"
    MAX_UPLOAD_MB: int = 50
    DEFAULT_QUOTA_MB: int = 500

    # --- email -----------------------------------------------------------
    SMTP_HOST: str = ""          # empty => dev outbox (files in data/outbox + log)
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_TLS: bool = True
    MAIL_FROM: str = "TrustShare <no-reply@trustshare.local>"
    OUTBOX_DIR: str = str(BASE_DIR / "data" / "outbox")

    # --- rate limiting / monitoring --------------------------------------
    RATE_LIMIT_PER_MINUTE: int = 120
    AUTH_RATE_LIMIT_PER_MINUTE: int = 20
    REMINDER_HOURS: int = 24
    REMINDER_INTERVAL_SECONDS: int = 600
    RUN_BACKGROUND_JOBS: bool = True
    AUTO_CREATE_TABLES: bool = True   # set false when using `alembic upgrade head`

    @property
    def is_prod(self) -> bool:
        return self.ENV.lower() in ("prod", "production")

    @property
    def cors_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
