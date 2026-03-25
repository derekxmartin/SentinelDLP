import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from server.schemas.base import (
    CamelModel,
    ConditionTypeEnum,
    ExceptionScopeEnum,
    MessageComponentEnum,
    PaginatedResponse,
    PolicyStatusEnum,
    SeverityEnum,
)


# --- Rule Condition ---


class RuleConditionCreate(BaseModel):
    condition_type: ConditionTypeEnum
    component: MessageComponentEnum = MessageComponentEnum.GENERIC
    config: dict
    match_count_min: int = Field(default=1, ge=1)


class RuleConditionResponse(CamelModel):
    id: uuid.UUID
    condition_type: ConditionTypeEnum
    component: MessageComponentEnum
    config: dict
    match_count_min: int


# --- Detection Rule ---


class DetectionRuleCreate(BaseModel):
    name: str = Field(max_length=255)
    description: str | None = None
    rule_type: str = Field(pattern=r"^(detection|group)$")
    conditions: list[RuleConditionCreate] = []


class DetectionRuleResponse(CamelModel):
    id: uuid.UUID
    name: str
    description: str | None
    rule_type: str
    conditions: list[RuleConditionResponse] = []


# --- Exception Condition ---


class ExceptionConditionCreate(BaseModel):
    condition_type: ConditionTypeEnum
    component: MessageComponentEnum = MessageComponentEnum.GENERIC
    config: dict
    match_count_min: int = Field(default=1, ge=1)


class ExceptionConditionResponse(CamelModel):
    id: uuid.UUID
    condition_type: ConditionTypeEnum
    component: MessageComponentEnum
    config: dict
    match_count_min: int


# --- Policy Exception ---


class PolicyExceptionCreate(BaseModel):
    name: str = Field(max_length=255)
    description: str | None = None
    scope: ExceptionScopeEnum = ExceptionScopeEnum.ENTIRE_MESSAGE
    exception_type: str = Field(pattern=r"^(detection|group)$")
    conditions: list[ExceptionConditionCreate] = []


class PolicyExceptionResponse(CamelModel):
    id: uuid.UUID
    name: str
    description: str | None
    scope: ExceptionScopeEnum
    exception_type: str
    conditions: list[ExceptionConditionResponse] = []


# --- Severity Threshold ---


class SeverityThreshold(BaseModel):
    threshold: int = Field(ge=1)
    severity: SeverityEnum


# --- Policy Group ---


class PolicyGroupCreate(BaseModel):
    name: str = Field(max_length=255)
    description: str | None = None


class PolicyGroupResponse(CamelModel):
    id: uuid.UUID
    name: str
    description: str | None


# --- Policy ---


class PolicyCreate(BaseModel):
    name: str = Field(max_length=255)
    description: str | None = None
    severity: SeverityEnum = SeverityEnum.MEDIUM
    group_id: uuid.UUID | None = None
    response_rule_id: uuid.UUID | None = None
    severity_thresholds: list[SeverityThreshold] | None = None
    ttd_fallback: str = Field(default="log", pattern=r"^(allow|block|log)$")
    detection_rules: list[DetectionRuleCreate] = []
    exceptions: list[PolicyExceptionCreate] = []


class PolicyUpdate(BaseModel):
    name: str | None = Field(default=None, max_length=255)
    description: str | None = None
    severity: SeverityEnum | None = None
    group_id: uuid.UUID | None = None
    response_rule_id: uuid.UUID | None = None
    severity_thresholds: list[SeverityThreshold] | None = None
    ttd_fallback: str | None = Field(default=None, pattern=r"^(allow|block|log)$")


class PolicyResponse(CamelModel):
    id: uuid.UUID
    name: str
    description: str | None
    status: PolicyStatusEnum
    severity: SeverityEnum
    is_template: bool
    template_name: str | None
    severity_thresholds: list[SeverityThreshold] | None
    ttd_fallback: str
    group: PolicyGroupResponse | None = None
    response_rule_id: uuid.UUID | None
    detection_rules: list[DetectionRuleResponse] = []
    exceptions: list[PolicyExceptionResponse] = []
    created_at: datetime
    updated_at: datetime


class PolicyListResponse(PaginatedResponse):
    items: list[PolicyResponse]
