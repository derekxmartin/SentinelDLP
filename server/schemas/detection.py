import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from server.schemas.base import CamelModel, SeverityEnum


# --- Data Identifier ---

class DataIdentifierCreate(BaseModel):
    name: str = Field(max_length=255)
    description: str | None = None
    config: dict
    is_active: bool = True


class DataIdentifierResponse(CamelModel):
    id: uuid.UUID
    name: str
    description: str | None
    config: dict
    is_builtin: bool
    is_active: bool
    created_at: datetime
    updated_at: datetime


# --- Keyword Dictionary ---

class KeywordDictionaryCreate(BaseModel):
    name: str = Field(max_length=255)
    description: str | None = None
    config: dict
    is_active: bool = True


class KeywordDictionaryResponse(CamelModel):
    id: uuid.UUID
    name: str
    description: str | None
    config: dict
    is_active: bool
    created_at: datetime
    updated_at: datetime


# --- Detect API ---

class DetectRequest(BaseModel):
    content: str
    policy_ids: list[uuid.UUID] | None = None


class DetectFileRequest(BaseModel):
    policy_ids: list[uuid.UUID] | None = None


class DetectMatch(CamelModel):
    identifier: str
    pattern: str | None = None
    matches: list[str]
    count: int
    component: str


class DetectResult(CamelModel):
    policy_id: uuid.UUID
    policy_name: str
    severity: SeverityEnum
    matched: bool
    matches: list[DetectMatch] = []
    match_count: int = 0


class DetectResponse(CamelModel):
    results: list[DetectResult]
    total_matches: int


# --- Fingerprint ---

class FingerprintCreate(BaseModel):
    name: str = Field(max_length=255)
    description: str | None = None


class FingerprintResponse(CamelModel):
    id: uuid.UUID
    name: str
    description: str | None
    hash_value: str
    created_at: datetime
