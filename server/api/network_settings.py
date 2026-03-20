"""Network monitor settings API — GET/PUT /api/settings/network (P5-T5).

Manages configuration for the HTTP proxy and SMTP relay services.
Settings are persisted to a JSON file and served to the console.
Network services read these at startup via environment variables;
runtime changes require service restart to take effect.
"""

from __future__ import annotations

import json
import logging
from enum import Enum
from pathlib import Path

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from server.api.dependencies import RequirePermission
from server.schemas.base import CamelModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/settings", tags=["settings"])

SETTINGS_FILE = Path(__file__).resolve().parent.parent.parent / "data" / "network_settings.json"


class NetworkMode(str, Enum):
    MONITOR = "monitor"
    PREVENT = "prevent"


class HttpProxySettings(CamelModel):
    mode: NetworkMode = NetworkMode.MONITOR
    block_threshold: int = Field(default=1, ge=1, le=100)
    domain_allowlist: list[str] = []


class SmtpRelaySettings(CamelModel):
    mode: NetworkMode = NetworkMode.MONITOR
    upstream_host: str = "mailhog"
    upstream_port: int = Field(default=1025, ge=1, le=65535)
    block_threshold: int = Field(default=5, ge=1, le=100)
    modify_threshold: int = Field(default=1, ge=1, le=100)
    quarantine_address: str = "quarantine@dlp.local"


class NetworkSettingsResponse(CamelModel):
    http_proxy: HttpProxySettings = HttpProxySettings()
    smtp_relay: SmtpRelaySettings = SmtpRelaySettings()


class NetworkSettingsUpdate(BaseModel):
    http_proxy: HttpProxySettings | None = None
    smtp_relay: SmtpRelaySettings | None = None


def _load_settings() -> NetworkSettingsResponse:
    """Load settings from JSON file, returning defaults if missing."""
    if SETTINGS_FILE.exists():
        try:
            data = json.loads(SETTINGS_FILE.read_text())
            return NetworkSettingsResponse(**data)
        except (json.JSONDecodeError, Exception) as e:
            logger.warning("Failed to load network settings: %s", e)
    return NetworkSettingsResponse()


def _save_settings(settings: NetworkSettingsResponse) -> None:
    """Persist settings to JSON file."""
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(settings.model_dump(), indent=2))


@router.get("/network", response_model=NetworkSettingsResponse)
async def get_network_settings(
    user=Depends(RequirePermission("system:admin")),
):
    """Get current network monitor settings."""
    return _load_settings()


@router.put("/network", response_model=NetworkSettingsResponse)
async def update_network_settings(
    body: NetworkSettingsUpdate,
    user=Depends(RequirePermission("system:admin")),
):
    """Update network monitor settings.

    Only provided sections are updated; omitted sections keep current values.
    Changes require service restart to take effect.
    """
    current = _load_settings()

    if body.http_proxy is not None:
        current.http_proxy = body.http_proxy
    if body.smtp_relay is not None:
        current.smtp_relay = body.smtp_relay

    _save_settings(current)
    logger.info("Network settings updated by %s", user.username)
    return current
