from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    model_config = {"env_prefix": "DLP_"}

    # Database
    database_url: str = "postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel_dlp"

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # gRPC
    grpc_port: int = 50051

    # SIEM
    siem_endpoint: str = "http://localhost:9200/api/v1/ingest"
    siem_api_key: str = ""

    # CORS
    cors_origins: list[str] = ["http://localhost:3000"]

    # Auth
    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False


settings = Settings()
