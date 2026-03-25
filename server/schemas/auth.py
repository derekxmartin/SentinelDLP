import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field

from server.schemas.base import CamelModel


# --- Login ---


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(CamelModel):
    access_token: str
    token_type: str = "bearer"
    mfa_required: bool = False
    mfa_challenge_token: str | None = None


class MFAVerifyRequest(BaseModel):
    mfa_challenge_token: str
    totp_code: str = Field(min_length=6, max_length=6)


class TokenRefreshResponse(CamelModel):
    access_token: str
    token_type: str = "bearer"


# --- MFA Enrollment ---


class MFAEnrollResponse(CamelModel):
    secret: str
    qr_uri: str


class MFAEnrollVerifyRequest(BaseModel):
    totp_code: str = Field(min_length=6, max_length=6)


class MFADisableRequest(BaseModel):
    password: str


# --- User ---


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8)
    full_name: str | None = None
    role_id: uuid.UUID


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    full_name: str | None = None
    is_active: bool | None = None
    role_id: uuid.UUID | None = None


class UserResponse(CamelModel):
    id: uuid.UUID
    username: str
    email: str
    full_name: str | None
    is_active: bool
    mfa_enabled: bool
    role_id: uuid.UUID
    role_name: str | None = None
    created_at: datetime
    updated_at: datetime


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)


# --- Role ---


class RoleResponse(CamelModel):
    id: uuid.UUID
    name: str
    description: str | None


# --- Current User ---


class MeResponse(CamelModel):
    id: uuid.UUID
    username: str
    email: str
    full_name: str | None
    mfa_enabled: bool
    role: RoleResponse
