"""Security monitoring + suspicious-activity detection."""
from datetime import timedelta
from typing import Optional
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from . import cache, audit
from .config import settings
from .database import utcnow
from .models import LoginEvent, SecurityEvent, User, DownloadEvent
from .notifications import notify

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def security_event(db: Session, type_: str, message: str, severity: str = "medium", user_id: Optional[str] = None,
                   ip: str = "", notify_user: bool = True, **details) -> SecurityEvent:
    ev = SecurityEvent(type=type_, severity=severity, message=message, user_id=user_id, ip=ip, details=details)
    db.add(ev); db.commit()
    audit.log(db, f"security.{type_}", actor_id=user_id, resource_type="security", resource_id=ev.id, ip=ip,
              severity=severity, message=message)
    if SEVERITY_RANK.get(severity, 2) >= 2:
        if user_id and notify_user:
            notify(db, user_id, "security", f"Security warning: {type_.replace('_', ' ')}", message, "/dashboard?tab=security")
        for admin in db.scalars(select(User).where(User.role == "admin", User.is_active == True)).all():  # noqa: E712
            if admin.id != user_id and SEVERITY_RANK[severity] >= 3:
                notify(db, admin, "security", f"[admin] {type_.replace('_', ' ')}", message, "/dashboard?tab=admin", email=False)
    return ev


def record_login(db: Session, email: str, success: bool, ip: str, ua: str, user: Optional[User] = None,
                 method: str = "password", reason: str = ""):
    db.add(LoginEvent(user_id=user.id if user else None, email=email[:255], success=success, method=method,
                      reason=reason, ip=ip, user_agent=ua[:255]))
    db.commit()
    audit.log(db, "auth.login.success" if success else "auth.login.failed", actor_id=user.id if user else None,
              resource_type="user", resource_id=user.id if user else email, ip=ip,
              severity="info" if success else "warning", method=method, reason=reason)
    since = utcnow() - timedelta(minutes=10)
    if not success:
        by_ip = db.scalar(select(func.count()).select_from(LoginEvent).where(
            LoginEvent.ip == ip, LoginEvent.success == False, LoginEvent.ts >= since)) or 0  # noqa: E712
        if by_ip == settings.MAX_FAILED_LOGINS:
            security_event(db, "brute_force_ip", f"{by_ip} failed logins from {ip} in 10 minutes", "high",
                           user.id if user else None, ip, attempts=by_ip)
        if user:
            by_user = db.scalar(select(func.count()).select_from(LoginEvent).where(
                LoginEvent.user_id == user.id, LoginEvent.success == False, LoginEvent.ts >= since)) or 0  # noqa: E712
            if by_user == 3:
                security_event(db, "repeated_failed_login", "Several failed sign-in attempts on your account.",
                               "medium", user.id, ip, attempts=by_user)
    elif user:
        prev_ip = user.last_login_ip
        if prev_ip and prev_ip != ip:
            known = db.scalar(select(func.count()).select_from(LoginEvent).where(
                LoginEvent.user_id == user.id, LoginEvent.success == True, LoginEvent.ip == ip,  # noqa: E712
                LoginEvent.ts < utcnow() - timedelta(seconds=1))) or 0
            if not known:
                security_event(db, "new_ip_login", f"Sign-in from a new network address ({ip}).", "low", user.id, ip,
                               notify_user=False)


def check_download_spike(db: Session, owner_id: str, user_id: Optional[str], ip: str, limit: int = 25):
    n = cache.incr(f"dlspike:{user_id or ip}", 60)
    if n == limit:
        security_event(db, "download_spike", f"Unusually many downloads ({n}/min) from {user_id or ip}.", "high",
                       owner_id, ip, downloads_per_minute=n)


def check_link_probing(db: Session, ip: str, limit: int = 10):
    n = cache.incr(f"probe:{ip}", 600)
    if n == limit:
        security_event(db, "link_probing", f"{n} invalid/blocked share-link attempts from {ip}.", "high", None, ip,
                       attempts=n)
