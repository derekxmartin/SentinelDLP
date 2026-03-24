"""Pydantic schemas for Discover scan API (P7-T5)."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from server.schemas.base import CamelModel, PaginatedResponse


class DiscoverStatusEnum(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class DiscoverCreate(BaseModel):
    name: str = Field(max_length=255)
    agent_id: uuid.UUID | None = None
    scan_path: str = Field(max_length=1024)
    recursive: bool = True
    file_extensions: list[str] | None = None
    path_exclusions: list[str] | None = None


class DiscoverUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=255)
    agent_id: uuid.UUID | None = None
    scan_path: str | None = Field(default=None, max_length=1024)
    recursive: bool | None = None
    file_extensions: list[str] | None = None
    path_exclusions: list[str] | None = None


class DiscoverComplete(BaseModel):
    files_examined: int = 0
    files_scanned: int = 0
    violations_found: int = 0
    files_quarantined: int = 0
    duration_ms: int | None = None
    findings: list[dict] | None = None


class DiscoverResponse(CamelModel):
    id: uuid.UUID
    name: str
    status: DiscoverStatusEnum
    agent_id: uuid.UUID | None = None
    scan_path: str
    recursive: bool
    file_extensions: list[str] | None = None
    path_exclusions: list[str] | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    files_examined: int
    files_scanned: int
    violations_found: int
    files_quarantined: int
    duration_ms: int | None = None
    findings: list[dict] | None = None
    created_at: datetime
    updated_at: datetime


class DiscoverListResponse(PaginatedResponse):
    items: list[DiscoverResponse]
