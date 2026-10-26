from datetime import datetime
from typing import Optional, Literal
from pydantic import BaseModel, EmailStr, Field, field_validator, ConfigDict
from .security import password_problems


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class RegisterIn(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=32, pattern=r"^[A-Za-z0-9_.-]+$")
    full_name: str = Field(default="", max_length=128)
    password: str

    @field_validator("password")
    @classmethod
    def strong(cls, v):
        p = password_problems(v)
        if p: raise ValueError("Password needs " + ", ".join(p))
        return v


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class MfaVerifyIn(BaseModel):
    mfa_token: str
    code: str


class RefreshIn(BaseModel):
    refresh_token: str


class ForgotIn(BaseModel):
    email: EmailStr


class ResetIn(BaseModel):
    token: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def strong(cls, v):
        p = password_problems(v)
        if p: raise ValueError("Password needs " + ", ".join(p))
        return v


class ChangePasswordIn(ResetIn):
    token: str = ""           # unused; reused validator
    current_password: str


class MfaCodeIn(BaseModel):
    code: str


class MfaDisableIn(BaseModel):
    password: str = ""
    code: str


class UserOut(ORM):
    id: str; email: str; username: str; full_name: str; role: str; mfa_enabled: bool
    notify_email: bool; is_active: bool; created_at: datetime; last_login_at: Optional[datetime] = None
    quota_bytes: int; oauth_provider: Optional[str] = None


class ProfileIn(BaseModel):
    full_name: Optional[str] = Field(default=None, max_length=128)
    notify_email: Optional[bool] = None


class FolderIn(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    parent_id: Optional[str] = None


class FolderPatch(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    parent_id: Optional[str] = None
    move_to_root: bool = False


class FolderOut(ORM):
    id: str; name: str; parent_id: Optional[str]; created_at: datetime


class FileOut(ORM):
    id: str; name: str; category: str; mime_type: str; size: int; current_version: int
    folder_id: Optional[str]; description: str; tags: list; created_at: datetime; updated_at: datetime
    owner_id: str
    permission: str = "owner"
    owner_name: str = ""


class FilePatch(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    folder_id: Optional[str] = None
    move_to_root: bool = False
    category: Optional[str] = None
    description: Optional[str] = Field(default=None, max_length=2000)
    tags: Optional[list[str]] = None


class VersionOut(ORM):
    id: str; version: int; size: int; sha256: str; key_version: int; created_at: datetime; uploaded_by: str


class LinkIn(BaseModel):
    permission: Literal["view", "download"] = "download"
    expires_in_hours: Optional[float] = Field(default=24, gt=0, le=24 * 365)
    max_downloads: Optional[int] = Field(default=None, ge=1, le=100000)
    password: Optional[str] = Field(default=None, min_length=4, max_length=128)
    allowed_email: Optional[EmailStr] = None
    note: str = Field(default="", max_length=255)


class LinkOut(ORM):
    id: str; file_id: str; permission: str; expires_at: Optional[datetime]; max_downloads: Optional[int]
    download_count: int; view_count: int; allowed_email: Optional[str]; note: str; revoked: bool
    created_at: datetime; token_hint: str
    has_password: bool = False
    status: str = "active"
    token: Optional[str] = None
    url: Optional[str] = None


class ShareIn(BaseModel):
    email: EmailStr
    permission: Literal["view", "download", "edit"] = "download"
    expires_in_hours: Optional[float] = Field(default=None, gt=0, le=24 * 365)


class ShareOut(BaseModel):
    id: str; user_id: str; email: str; username: str; permission: str; expires_at: Optional[datetime]
    created_at: datetime
