import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import (BigInteger, Boolean, DateTime, ForeignKey, Integer, String, Text, JSON, Index,
                        UniqueConstraint)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .database import Base, utcnow


def uid() -> str:
    return uuid.uuid4().hex


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(128), default="")
    password_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    role: Mapped[str] = mapped_column(String(16), default="user")  # admin | user | viewer
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    notify_email: Mapped[bool] = mapped_column(Boolean, default=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    mfa_backup_codes: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)  # sha256 hashes
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    oauth_provider: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    oauth_sub: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    quota_bytes: Mapped[int] = mapped_column(BigInteger, default=500 * 1024 * 1024)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_login_ip: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    __table_args__ = (UniqueConstraint("oauth_provider", "oauth_sub", name="uq_oauth"),)


class AuthSession(Base):
    """A refresh-token session (one per device/login)."""
    __tablename__ = "auth_sessions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)  # = refresh jti
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_used_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class PasswordReset(Base):
    __tablename__ = "password_resets"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Folder(Base):
    __tablename__ = "folders"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    parent_id: Mapped[Optional[str]] = mapped_column(ForeignKey("folders.id", ondelete="CASCADE"), nullable=True)
    name: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class File(Base):
    __tablename__ = "files"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    folder_id: Mapped[Optional[str]] = mapped_column(ForeignKey("folders.id", ondelete="SET NULL"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    category: Mapped[str] = mapped_column(String(32), default="other", index=True)
    mime_type: Mapped[str] = mapped_column(String(128), default="application/octet-stream")
    size: Mapped[int] = mapped_column(BigInteger, default=0)
    current_version: Mapped[int] = mapped_column(Integer, default=1)
    description: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)
    versions: Mapped[list["FileVersion"]] = relationship(cascade="all, delete-orphan", order_by="FileVersion.version")


class FileVersion(Base):
    __tablename__ = "file_versions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    file_id: Mapped[str] = mapped_column(ForeignKey("files.id", ondelete="CASCADE"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    storage_key: Mapped[str] = mapped_column(String(255))
    size: Mapped[int] = mapped_column(BigInteger)          # plaintext size
    sha256: Mapped[str] = mapped_column(String(64))        # plaintext integrity hash
    wrapped_key: Mapped[str] = mapped_column(Text)         # per-file AES-256 key, wrapped by master key
    key_version: Mapped[int] = mapped_column(Integer)
    uploaded_by: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    __table_args__ = (UniqueConstraint("file_id", "version", name="uq_file_version"),)


class FileShare(Base):
    """Direct share with a registered user, with an access level."""
    __tablename__ = "file_shares"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    file_id: Mapped[str] = mapped_column(ForeignKey("files.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    permission: Mapped[str] = mapped_column(String(16), default="download")  # view | download | edit
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    __table_args__ = (UniqueConstraint("file_id", "user_id", name="uq_file_user_share"),)


class ShareLink(Base):
    __tablename__ = "share_links"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    file_id: Mapped[str] = mapped_column(ForeignKey("files.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    token_hint: Mapped[str] = mapped_column(String(8), default="")
    permission: Mapped[str] = mapped_column(String(16), default="download")  # view | download
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    max_downloads: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    download_count: Mapped[int] = mapped_column(Integer, default=0)
    view_count: Mapped[int] = mapped_column(Integer, default=0)
    password_hash: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    allowed_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    note: Mapped[str] = mapped_column(String(255), default="")
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    reminder_sent: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[str] = mapped_column(String(32))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    file: Mapped["File"] = relationship()


class DownloadEvent(Base):
    __tablename__ = "download_events"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    file_id: Mapped[str] = mapped_column(String(32), index=True)
    owner_id: Mapped[str] = mapped_column(String(32), index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    user_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    link_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    kind: Mapped[str] = mapped_column(String(16), default="download")  # download | view
    ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="")
    bytes: Mapped[int] = mapped_column(BigInteger, default=0)


class LoginEvent(Base):
    __tablename__ = "login_events"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    email: Mapped[str] = mapped_column(String(255), default="")
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    method: Mapped[str] = mapped_column(String(16), default="password")  # password | mfa | oauth
    reason: Mapped[str] = mapped_column(String(64), default="")
    ip: Mapped[str] = mapped_column(String(64), default="", index=True)
    user_agent: Mapped[str] = mapped_column(String(255), default="")


class SecurityEvent(Base):
    __tablename__ = "security_events"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    type: Mapped[str] = mapped_column(String(48), index=True)
    severity: Mapped[str] = mapped_column(String(16), default="medium")  # low | medium | high | critical
    message: Mapped[str] = mapped_column(String(512), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    resolved: Mapped[bool] = mapped_column(Boolean, default=False)


class Notification(Base):
    __tablename__ = "notifications"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(32))  # share | access | download | security | expiry | system
    title: Mapped[str] = mapped_column(String(200))
    message: Mapped[str] = mapped_column(String(1000), default="")
    link: Mapped[str] = mapped_column(String(255), default="")
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class AuditLogSQL(Base):
    """Audit trail fallback used when MongoDB is not configured/reachable."""
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=uid)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    actor_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)
    owner_id: Mapped[Optional[str]] = mapped_column(String(32), nullable=True, index=True)  # owner of the affected resource
    action: Mapped[str] = mapped_column(String(64), index=True)
    resource_type: Mapped[str] = mapped_column(String(32), default="")
    resource_id: Mapped[str] = mapped_column(String(64), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    severity: Mapped[str] = mapped_column(String(16), default="info")
    details: Mapped[dict] = mapped_column(JSON, default=dict)


Index("ix_files_owner_name", File.owner_id, File.name)
