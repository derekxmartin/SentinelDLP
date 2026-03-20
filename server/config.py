import logging

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_logger = logging.getLogger(__name__)

_INSECURE_JWT_SECRET = "change-me-in-production"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="DLP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Database ---
    database_url: str = "postgresql+asyncpg://akeso:akeso@localhost:5432/akeso_dlp"

    # --- Redis ---
    redis_url: str = "redis://localhost:6379/0"

    # --- gRPC ---
    grpc_host: str = "0.0.0.0"
    grpc_port: int = 50051
    grpc_tls_enabled: bool = False
    grpc_tls_ca_cert: str = ""
    grpc_tls_server_cert: str = ""
    grpc_tls_server_key: str = ""

    # --- SIEM Integration ---
    siem_enabled: bool = False
    siem_endpoint: str = "http://localhost:9200/api/v1/ingest"
    siem_api_key: str = ""
    siem_source_type: str = "akeso_dlp"
    siem_batch_size: int = 100
    siem_flush_interval_seconds: int = 10

    # --- Network Monitor ---
    network_http_proxy_enabled: bool = False
    network_http_proxy_port: int = 8080
    network_smtp_relay_enabled: bool = False
    network_smtp_relay_port: int = 2525
    network_smtp_upstream_host: str = "localhost"
    network_smtp_upstream_port: int = 1025

    # --- CORS ---
    cors_origins: list[str] = ["http://localhost:3000"]

    # --- Auth ---
    jwt_secret: str = Field(default=_INSECURE_JWT_SECRET)
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    login_rate_limit: int = 5
    login_rate_window_seconds: int = 30

    # --- Server ---
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False

    # --- Logging ---
    log_level: str = "info"
    log_format: str = "json"
    log_file: str = ""

    @model_validator(mode="after")
    def _warn_security_defaults(self) -> "Settings":
        """Log warnings for insecure default values.

        The validator intentionally does *not* raise so that module-level
        ``settings = Settings()`` never breaks imports in dev or CI.
        Use :func:`validate_production_config` at server startup to
        enforce hard failures in production.
        """
        if self.jwt_secret == _INSECURE_JWT_SECRET:
            if self.debug:
                _logger.warning(
                    "Using default JWT secret — acceptable for local "
                    "development only. Set DLP_JWT_SECRET for production."
                )
            else:
                _logger.critical(
                    "SECURITY: Default JWT secret in use with debug=False. "
                    "Set DLP_JWT_SECRET to a strong random value for "
                    "production."
                )
        if "akeso:akeso@" in self.database_url and not self.debug:
            _logger.warning(
                "Default database credentials detected — set "
                "DLP_DATABASE_URL with strong credentials for production."
            )
        return self


def validate_production_config() -> None:
    """Enforce production security requirements at server startup.

    Raises :class:`ValueError` if critical security defaults are
    detected in non-debug mode.
    """
    if settings.jwt_secret == _INSECURE_JWT_SECRET and not settings.debug:
        raise ValueError(
            "SECURITY: DLP_JWT_SECRET must be set to a strong random "
            "value in production. Set DLP_DEBUG=true to bypass this "
            "check in development."
        )


settings = Settings()
