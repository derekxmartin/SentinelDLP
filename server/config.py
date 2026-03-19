from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    jwt_secret: str = Field(default="change-me-in-production")
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


settings = Settings()
