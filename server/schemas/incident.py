import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from server.schemas.base import (
    CamelModel,
    ChannelEnum,
    IncidentStatusEnum,
    PaginatedResponse,
    SeverityEnum,
)


# --- Incident ---

class IncidentUpdate(BaseModel):
    status: IncidentStatusEnum | None = None
    severity: SeverityEnum | None = None
    custom_attributes: dict | None = None


class IncidentResponse(CamelModel):
    id: uuid.UUID
    policy_id: uuid.UUID | None
    policy_name: str
    severity: SeverityEnum
    status: IncidentStatusEnum
    channel: ChannelEnum
    source_type: str
    file_path: str | None
    file_name: str | None
    file_size: int | None
    file_type: str | None
    user: str | None
    source_ip: str | None
    destination: str | None
    match_count: int
    matched_content: dict | None
    data_identifiers: dict | None
    action_taken: str
    user_justification: str | None
    agent_id: uuid.UUID | None
    custom_attributes: dict | None
    created_at: datetime
    updated_at: datetime


class IncidentListResponse(PaginatedResponse):
    items: list[IncidentResponse]


# --- Incident Note ---

class IncidentNoteCreate(BaseModel):
    content: str = Field(min_length=1)


class IncidentNoteResponse(CamelModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    author_id: uuid.UUID | None
    content: str
    created_at: datetime


# --- Incident History ---

class IncidentHistoryResponse(CamelModel):
    id: uuid.UUID
    incident_id: uuid.UUID
    actor_id: uuid.UUID | None
    field: str
    old_value: str | None
    new_value: str | None
    created_at: str


# --- Smart Response ---

class SmartResponseRequest(BaseModel):
    action: str
    params: dict | None = None


class SmartResponseResult(CamelModel):
    success: bool
    action: str
    detail: str | None = None
