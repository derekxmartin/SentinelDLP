import uuid
from enum import Enum as PyEnum

from sqlalchemy import Enum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from server.models.base import Base, TimestampMixin, UUIDMixin


class ActionType(str, PyEnum):
    BLOCK = "block"
    NOTIFY = "notify"
    USER_CANCEL = "user_cancel"
    LOG = "log"
    QUARANTINE = "quarantine"


class ResponseRule(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "response_rules"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    actions: Mapped[list["ResponseAction"]] = relationship(
        back_populates="response_rule", cascade="all, delete-orphan"
    )


class ResponseAction(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "response_actions"

    action_type: Mapped[ActionType] = mapped_column(Enum(ActionType), nullable=False)
    # Action-specific config:
    #   block: {"recovery_path": "C:\\AkesoDLP\\Recovery"}
    #   notify: {"message": "...", "notification_type": "toast|balloon"}
    #   user_cancel: {"timeout_seconds": 120, "message": "..."}
    #   quarantine: {"quarantine_path": "..."}
    config: Mapped[dict | None] = mapped_column(JSONB)
    order: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    response_rule_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("response_rules.id", ondelete="CASCADE"),
        nullable=False,
    )
    response_rule: Mapped["ResponseRule"] = relationship(back_populates="actions")
