import uuid
from enum import Enum as PyEnum

from sqlalchemy import Boolean, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from server.models.base import Base, TimestampMixin, UUIDMixin


class PolicyStatus(str, PyEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DRAFT = "draft"


class Severity(str, PyEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ConditionType(str, PyEnum):
    REGEX = "regex"
    KEYWORD = "keyword"
    DATA_IDENTIFIER = "data_identifier"
    FILE_TYPE = "file_type"
    FINGERPRINT = "fingerprint"
    IDENTITY = "identity"


class MessageComponent(str, PyEnum):
    ENVELOPE = "envelope"
    SUBJECT = "subject"
    BODY = "body"
    ATTACHMENT = "attachment"
    GENERIC = "generic"


class ExceptionScope(str, PyEnum):
    ENTIRE_MESSAGE = "entire_message"
    MATCHED_COMPONENT = "matched_component"


class PolicyGroup(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "policy_groups"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    policies: Mapped[list["Policy"]] = relationship(back_populates="group")


class Policy(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "policies"

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[PolicyStatus] = mapped_column(
        Enum(PolicyStatus), default=PolicyStatus.DRAFT, nullable=False
    )
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity), default=Severity.MEDIUM, nullable=False
    )
    is_template: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    template_name: Mapped[str | None] = mapped_column(String(100))

    # Severity override by match count: [{"threshold": 100, "severity": "high"}, ...]
    severity_thresholds: Mapped[dict | None] = mapped_column(JSONB)

    # TTD fallback behavior
    ttd_fallback: Mapped[str] = mapped_column(String(10), default="log", nullable=False)

    # Group
    group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("policy_groups.id")
    )
    group: Mapped["PolicyGroup | None"] = relationship(back_populates="policies")

    # Response rule
    response_rule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("response_rules.id")
    )
    response_rule: Mapped["ResponseRule | None"] = relationship()

    # Relationships
    detection_rules: Mapped[list["DetectionRule"]] = relationship(
        back_populates="policy", cascade="all, delete-orphan"
    )
    exceptions: Mapped[list["PolicyException"]] = relationship(
        back_populates="policy", cascade="all, delete-orphan"
    )


class DetectionRule(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "detection_rules"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    rule_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # "detection" or "group"

    policy_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("policies.id", ondelete="CASCADE"),
        nullable=False,
    )
    policy: Mapped["Policy"] = relationship(back_populates="detection_rules")

    conditions: Mapped[list["RuleCondition"]] = relationship(
        back_populates="detection_rule", cascade="all, delete-orphan"
    )


class RuleCondition(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "rule_conditions"

    condition_type: Mapped[ConditionType] = mapped_column(
        Enum(ConditionType), nullable=False
    )
    component: Mapped[MessageComponent] = mapped_column(
        Enum(MessageComponent), default=MessageComponent.GENERIC, nullable=False
    )
    # Type-specific config stored as JSONB:
    #   regex: {"pattern": "...", "flags": "..."}
    #   keyword: {"dictionary_id": "...", "match_mode": "exact|proximity", "proximity": 10}
    #   data_identifier: {"identifier_id": "...", "min_matches": 1}
    #   file_type: {"types": ["pdf", "docx", ...]}
    #   fingerprint: {"fingerprint_id": "..."}
    #   identity: {"field": "sender_email", "operator": "equals", "value": "..."}
    config: Mapped[dict] = mapped_column(JSONB, nullable=False)

    match_count_min: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    detection_rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("detection_rules.id", ondelete="CASCADE"),
        nullable=False,
    )
    detection_rule: Mapped["DetectionRule"] = relationship(back_populates="conditions")


class PolicyException(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "policy_exceptions"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    scope: Mapped[ExceptionScope] = mapped_column(
        Enum(ExceptionScope), default=ExceptionScope.ENTIRE_MESSAGE, nullable=False
    )
    exception_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # "detection" or "group"

    policy_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("policies.id", ondelete="CASCADE"),
        nullable=False,
    )
    policy: Mapped["Policy"] = relationship(back_populates="exceptions")

    conditions: Mapped[list["ExceptionCondition"]] = relationship(
        back_populates="policy_exception", cascade="all, delete-orphan"
    )


class ExceptionCondition(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "exception_conditions"

    condition_type: Mapped[ConditionType] = mapped_column(
        Enum(ConditionType), nullable=False
    )
    component: Mapped[MessageComponent] = mapped_column(
        Enum(MessageComponent), default=MessageComponent.GENERIC, nullable=False
    )
    config: Mapped[dict] = mapped_column(JSONB, nullable=False)
    match_count_min: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    policy_exception_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("policy_exceptions.id", ondelete="CASCADE"),
        nullable=False,
    )
    policy_exception: Mapped["PolicyException"] = relationship(
        back_populates="conditions"
    )


# Forward reference for Policy.response_rule
from server.models.response import ResponseRule  # noqa: E402, F401
