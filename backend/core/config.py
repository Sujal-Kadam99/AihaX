"""AihaX application configuration."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "AihaX"
    app_version: str = "1.0.0"
    debug: bool = False

    # Environment mode: "local" or "cloud"
    environment: str = "local"

    redis_url: str = "redis://localhost:6379"
    database_url: str = "sqlite:///./db/aihax.db"
    chroma_path: str = "./db/chroma"
    reports_path: str = "./reports"
    config_path: str = "./config"

    claude_model: str = "claude-sonnet-4-6"
    claude_max_concurrent: int = 5
    claude_timeout: int = 30

    # Rate Limiting Configuration
    rate_limit_auth_max_attempts: int = 5
    rate_limit_auth_window: int = 60
    rate_limit_auth_backoff_base: float = 2.0
    rate_limit_auth_backoff_factor: float = 2.0
    rate_limit_public_max_requests: int = 30
    rate_limit_public_window: int = 60
    rate_limit_authenticated_max_requests: int = 120
    rate_limit_authenticated_window: int = 60

    # Authentication Configuration
    google_client_id: str = ""
    jwt_secret_key: str = ""
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 30
    dev_mock_auth: bool = False

    # Entitlement tokens are signed by the cloud issuer and verified locally
    # with a public key. The private key must never be shipped to desktop apps.
    entitlement_signing_private_key: str | None = None
    entitlement_verification_public_key: str | None = None
    entitlement_issuer: str = "aihax-entitlement-service"

    # Cloud secrets - optional in local mode, required in cloud mode
    stripe_secret_key: str | None = None
    stripe_public_key: str | None = None
    stripe_webhook_secret: str | None = None
    stripe_price_pro_monthly: str | None = None
    stripe_price_pro_onetime: str | None = None
    stripe_price_team_monthly: str | None = None
    stripe_price_agency_monthly: str | None = None
    stripe_price_enterprise_monthly: str | None = None
    # Comma-separated exact origins allowed as Stripe checkout return targets.
    # Local desktop development has a localhost fallback; cloud deployments
    # must explicitly configure their app origin(s).
    billing_return_origins: str = ""
    # Simulated subscriptions are for isolated local development only and are
    # disabled unless explicitly enabled in the environment.
    dev_mock_billing: bool = False

    # Owner / Freemium Configuration
    owner_email: str = ""
    free_tier_monthly_scans: int = 3

    # Encryption
    aihax_master_key: str = ""
    aihax_redis_password: str = ""

    class Config:
        env_file = ".env"
        extra = "ignore"

    def model_post_init(self, __context) -> None:
        if self.dev_mock_auth and self.environment.lower() in ("production", "cloud"):
            raise ValueError("FATAL: DEV_MOCK_AUTH cannot be enabled when environment is production or cloud!")
        if self.environment.strip().casefold() == "cloud":
            if not self.google_client_id:
                raise ValueError("google_client_id is required in cloud environment")
            if not self.stripe_secret_key:
                raise ValueError("stripe_secret_key is required in cloud environment")
            if not self.aihax_master_key:
                raise ValueError("aihax_master_key is required in cloud environment")
            if not self.entitlement_signing_private_key:
                raise ValueError("entitlement_signing_private_key is required in cloud environment")
            if not self.entitlement_verification_public_key:
                raise ValueError("entitlement_verification_public_key is required in cloud environment")
        if not self.jwt_secret_key:
            raise ValueError("jwt_secret_key environment variable is required")


@lru_cache
def get_settings() -> Settings:
    return Settings()


def ensure_directories(settings: Settings) -> None:
    """Create required directories if they don't exist."""
    for path in [
        settings.reports_path,
        settings.config_path,
        Path(settings.database_url.replace("sqlite:///", "")).parent,
        settings.chroma_path,
    ]:
        Path(path).mkdir(parents=True, exist_ok=True)
