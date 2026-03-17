import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict


class CamelModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


# --- Enums ---

class PolicyStatusEnum(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DRAFT = "draft"


class SeverityEnum(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ConditionTypeEnum(str, Enum):
    REGEX = "regex"
    KEYWORD = "keyword"
    DATA_IDENTIFIER = "data_identifier"
    FILE_TYPE = "file_type"
    FINGERPRINT = "fingerprint"
    IDENTITY = "identity"


class MessageComponentEnum(str, Enum):
    ENVELOPE = "envelope"
    SUBJECT = "subject"
    BODY = "body"
    ATTACHMENT = "attachment"
    GENERIC = "generic"


class ExceptionScopeEnum(str, Enum):
    ENTIRE_MESSAGE = "entire_message"
    MATCHED_COMPONENT = "matched_component"


class ActionTypeEnum(str, Enum):
    BLOCK = "block"
    NOTIFY = "notify"
    USER_CANCEL = "user_cancel"
    LOG = "log"
    QUARANTINE = "quarantine"


class IncidentStatusEnum(str, Enum):
    NEW = "new"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"
    ESCALATED = "escalated"


class ChannelEnum(str, Enum):
    USB = "usb"
    NETWORK_SHARE = "network_share"
    CLIPBOARD = "clipboard"
    BROWSER_UPLOAD = "browser_upload"
    EMAIL = "email"
    HTTP_UPLOAD = "http_upload"
    DISCOVER = "discover"


class AgentStatusEnum(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    STALE = "stale"
    ERROR = "error"


# --- Pagination ---

class PaginationParams(BaseModel):
    page: int = 1
    page_size: int = 25


class PaginatedResponse(CamelModel):
    total: int
    page: int
    page_size: int
    pages: int
