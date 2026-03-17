import uuid
from enum import Enum as PyEnum

from sqlalchemy import Enum, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from server.models.base import Base, TimestampMixin, UUIDMixin


class AgentStatus(str, PyEnum):
    ONLINE = "online"
    OFFLINE = "offline"
    STALE = "stale"
    ERROR = "error"


class AgentGroup(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "agent_groups"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    agents: Mapped[list["Agent"]] = relationship(back_populates="group")


class Agent(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "agents"

    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    os_version: Mapped[str | None] = mapped_column(String(255))
    agent_version: Mapped[str | None] = mapped_column(String(50))
    driver_version: Mapped[str | None] = mapped_column(String(50))
    policy_version: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45))
    status: Mapped[AgentStatus] = mapped_column(
        Enum(AgentStatus), default=AgentStatus.OFFLINE, nullable=False, index=True
    )
    last_heartbeat: Mapped[str | None] = mapped_column(String(50))  # ISO timestamp

    # Group
    group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("agent_groups.id")
    )
    group: Mapped["AgentGroup | None"] = relationship(back_populates="agents")

    # Agent capabilities / metadata
    capabilities: Mapped[dict | None] = mapped_column(JSONB)
