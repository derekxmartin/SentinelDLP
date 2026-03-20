"""Notification schemas for API request/response validation."""

import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel

from server.schemas.base import CamelModel, PaginatedResponse


class NotificationTypeEnum(str, Enum):
    INCIDENT_CREATED = "incident_created"
    POLICY_CHANGED = "policy_changed"
    AGENT_STATUS = "agent_status"
    SYSTEM = "system"


class NotificationSeverityEnum(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class NotificationResponse(CamelModel):
    id: uuid.UUID
    user_id: uuid.UUID
    type: NotificationTypeEnum
    severity: NotificationSeverityEnum
    title: str
    message: str
    resource_type: str | None
    resource_id: uuid.UUID | None
    is_read: bool
    created_at: datetime


class NotificationListResponse(PaginatedResponse):
    items: list[NotificationResponse]


class UnreadCountResponse(BaseModel):
    count: int
