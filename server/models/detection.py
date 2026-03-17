from sqlalchemy import Boolean, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from server.models.base import Base, TimestampMixin, UUIDMixin


class DataIdentifier(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "data_identifiers"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    # Pattern + validator config:
    #   {"pattern": "4[0-9]{12}(?:[0-9]{3})?", "validator": "luhn", "example": "4532015112830366"}
    config: Mapped[dict] = mapped_column(JSONB, nullable=False)
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class KeywordDictionary(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "keyword_dictionaries"

    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    # Keywords config:
    #   {"keywords": ["term1", "term2"], "case_sensitive": false, "match_mode": "exact|proximity", "proximity_distance": 10}
    config: Mapped[dict] = mapped_column(JSONB, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
