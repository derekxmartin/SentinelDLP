import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from server.schemas.base import AgentStatusEnum, CamelModel, PaginatedResponse


# --- Agent Group ---

class AgentGroupCreate(BaseModel):
    name: str = Field(max_length=255)
    description: str | None = None


class AgentGroupResponse(CamelModel):
    id: uuid.UUID
    name: str
    description: str | None


# --- Agent ---

class AgentResponse(CamelModel):
    id: uuid.UUID
    hostname: str
    os_version: str | None
    agent_version: str | None
    driver_version: str | None
    policy_version: int
    ip_address: str | None
    status: AgentStatusEnum
    last_heartbeat: str | None
    group: AgentGroupResponse | None = None
    capabilities: dict | None
    created_at: datetime
    updated_at: datetime


class AgentListResponse(PaginatedResponse):
    items: list[AgentResponse]
