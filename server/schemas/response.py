import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from server.schemas.base import ActionTypeEnum, CamelModel


# --- Response Action ---


class ResponseActionCreate(BaseModel):
    action_type: ActionTypeEnum
    config: dict | None = None
    order: int = 0


class ResponseActionResponse(CamelModel):
    id: uuid.UUID
    action_type: ActionTypeEnum
    config: dict | None
    order: int


# --- Response Rule ---


class ResponseRuleCreate(BaseModel):
    name: str = Field(max_length=255)
    description: str | None = None
    actions: list[ResponseActionCreate] = []


class ResponseRuleResponse(CamelModel):
    id: uuid.UUID
    name: str
    description: str | None
    actions: list[ResponseActionResponse] = []
    created_at: datetime
    updated_at: datetime
