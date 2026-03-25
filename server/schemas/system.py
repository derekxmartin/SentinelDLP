import uuid
from datetime import datetime

from pydantic import BaseModel

from server.schemas.base import CamelModel, PaginatedResponse


# --- Audit Log ---


class AuditLogResponse(CamelModel):
    id: uuid.UUID
    actor_id: uuid.UUID | None
    action: str
    resource_type: str
    resource_id: str | None
    detail: str | None
    changes: dict | None
    ip_address: str | None
    created_at: datetime


class AuditLogListResponse(PaginatedResponse):
    items: list[AuditLogResponse]


# --- Search ---


class SearchResult(CamelModel):
    category: str
    id: uuid.UUID
    title: str
    subtitle: str | None = None


class SearchResponse(CamelModel):
    query: str
    results: dict[str, list[SearchResult]]
    total: int


# --- Health ---


class HealthResponse(CamelModel):
    status: str
    service: str


# --- Report ---


class ReportGenerateRequest(BaseModel):
    report_type: str  # "summary" or "detail"
    date_from: datetime | None = None
    date_to: datetime | None = None
    policy_ids: list[uuid.UUID] | None = None
    channels: list[str] | None = None


class ReportResponse(CamelModel):
    id: uuid.UUID
    report_type: str
    status: str
    created_at: datetime


# --- Discover ---


class DiscoverScanCreate(BaseModel):
    name: str
    agent_group_ids: list[uuid.UUID] | None = None
    target_paths: list[str]
    schedule: str | None = None
    policy_ids: list[uuid.UUID] | None = None


class DiscoverScanResponse(CamelModel):
    id: uuid.UUID
    name: str
    status: str
    target_paths: list[str]
    created_at: datetime


# --- Template ---


class TemplateResponse(CamelModel):
    id: uuid.UUID
    name: str
    description: str | None
    severity: str
    template_name: str
