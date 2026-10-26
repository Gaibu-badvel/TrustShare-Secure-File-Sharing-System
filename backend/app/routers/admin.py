"""Admin dashboard: users, storage, security analytics, key rotation, system health & performance metrics."""
from collections import Counter
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from typing import Optional
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from .. import audit, cache, crypto, metrics, services
from ..config import settings
from ..database import get_db, utcnow
from ..deps import client_ip, require_admin
from ..models import AuthSession, DownloadEvent, File, FileVersion, LoginEvent, SecurityEvent, ShareLink, User
from ..reminders import send_expiry_reminders
from ..storage import get_storage

router = APIRouter(prefix="/api/admin", tags=["admin"], dependencies=[Depends(require_admin)])


class UserPatch(BaseModel):
    role: Optional[str] = None
    is_active: Optional[bool] = None
    quota_mb: Optional[int] = None
    unlock: bool = False


class RotateIn(BaseModel):
    reencrypt: bool = False   # True => also generate brand-new data keys and re-encrypt every blob


@router.get("/overview")
def overview(db: Session = Depends(get_db)):
    now = utcnow(); d1 = now - timedelta(days=1); d7 = now - timedelta(days=7)
    c = lambda q: db.scalar(q) or 0  # noqa: E731
    users = db.scalars(select(User)).all()
    storage_by_user = dict(db.execute(select(File.owner_id, func.coalesce(func.sum(FileVersion.size), 0)).join(FileVersion, FileVersion.file_id == File.id).group_by(File.owner_id)).all())
    ev = db.scalars(select(SecurityEvent).where(SecurityEvent.ts >= d7)).all()
    return {
        "users": {"total": len(users), "active": sum(u.is_active for u in users), "admins": sum(u.role == "admin" for u in users),
                  "mfa_enabled": sum(u.mfa_enabled for u in users), "new_7d": sum(1 for u in users if u.created_at >= d7),
                  "active_24h": c(select(func.count(func.distinct(LoginEvent.user_id))).where(LoginEvent.success == True, LoginEvent.ts >= d1))},  # noqa: E712
        "storage": {"files": c(select(func.count()).select_from(File)), "versions": c(select(func.count()).select_from(FileVersion)),
                    "total_bytes": c(select(func.coalesce(func.sum(FileVersion.size), 0))),
                    "top_users": sorted([{"user_id": k, "username": next((u.username for u in users if u.id == k), "?"), "bytes": v}
                                         for k, v in storage_by_user.items()], key=lambda x: -x["bytes"])[:5]},
        "sharing": {"links_active": sum(1 for l in db.scalars(select(ShareLink)) if l.revoked is False and (not l.expires_at or l.expires_at > now)),
                    "downloads_24h": c(select(func.count()).select_from(DownloadEvent).where(DownloadEvent.ts >= d1, DownloadEvent.kind == "download")),
                    "downloads_7d": c(select(func.count()).select_from(DownloadEvent).where(DownloadEvent.ts >= d7, DownloadEvent.kind == "download"))},
        "security": {"events_7d": len(ev), "open": sum(not e.resolved for e in ev), "by_severity": dict(Counter(e.severity for e in ev)),
                     "failed_logins_24h": c(select(func.count()).select_from(LoginEvent).where(LoginEvent.success == False, LoginEvent.ts >= d1)),  # noqa: E712
                     "active_sessions": c(select(func.count()).select_from(AuthSession).where(AuthSession.revoked == False, AuthSession.expires_at > now))},  # noqa: E712
    }


@router.get("/users")
def users(q: str = "", db: Session = Depends(get_db)):
    qry = select(User).order_by(User.created_at.desc())
    if q: qry = qry.where(func.lower(User.email).like(f"%{q.lower()}%") | func.lower(User.username).like(f"%{q.lower()}%"))
    return [{"id": u.id, "email": u.email, "username": u.username, "role": u.role, "is_active": u.is_active, "mfa_enabled": u.mfa_enabled,
             "created_at": u.created_at, "last_login_at": u.last_login_at, "locked": bool(u.locked_until and u.locked_until > utcnow()),
             "used_bytes": services.used_bytes(db, u.id), "quota_bytes": u.quota_bytes} for u in db.scalars(qry.limit(500))]


@router.patch("/users/{user_id}")
def patch_user(user_id: str, body: UserPatch, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    u = db.get(User, user_id)
    if not u: raise HTTPException(404, "User not found")
    if u.id == admin.id and (body.is_active is False or (body.role and body.role != "admin")):
        raise HTTPException(400, "You cannot demote or disable yourself")
    if body.role:
        if body.role not in ("admin", "user", "viewer"): raise HTTPException(400, "Invalid role")
        u.role = body.role
    if body.is_active is not None:
        u.is_active = body.is_active
        if not body.is_active:
            for s in db.scalars(select(AuthSession).where(AuthSession.user_id == u.id)): s.revoked = True
    if body.quota_mb: u.quota_bytes = body.quota_mb * 1024 * 1024
    if body.unlock: u.locked_until = None; u.failed_attempts = 0
    db.commit()
    audit.log(db, "admin.user.update", admin.id, "user", u.id, client_ip(request), severity="warning", changes=body.model_dump(exclude_none=True))
    return {"ok": True}


@router.get("/keys")
def key_status(db: Session = Depends(get_db)):
    usage = dict(db.execute(select(FileVersion.key_version, func.count()).group_by(FileVersion.key_version)).all())
    return {"active_version": crypto.active_version(), "versions": sorted(crypto.keys()), "blobs_per_key_version": usage,
            "algorithm": "AES-256-GCM (per-file data key, wrapped by master key)"}


@router.post("/keys/rotate")
def rotate_keys(body: RotateIn, request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    ver, env_b64 = crypto.add_master_key()
    rewrapped = reencrypted = 0
    for fv in db.scalars(select(FileVersion)).all():
        if body.reencrypt:
            f = db.get(File, fv.file_id)
            data = services.read_version(f, fv)
            blob, wrapped, kv, sha = crypto.encrypt_bytes(data, aad=f"{f.id}:{fv.version}".encode())
            get_storage().put(fv.storage_key, blob)
            fv.wrapped_key, fv.key_version, fv.sha256 = wrapped, kv, sha; reencrypted += 1
        elif fv.key_version != ver:
            fv.wrapped_key, fv.key_version = crypto.rewrap(fv.wrapped_key, fv.key_version, ver); rewrapped += 1
        db.commit()
    audit.log(db, "admin.keys.rotate", admin.id, "keys", str(ver), client_ip(request), severity="warning", rewrapped=rewrapped, reencrypted=reencrypted)
    out = {"new_version": ver, "rewrapped": rewrapped, "reencrypted": reencrypted}
    if env_b64: out["add_to_MASTER_KEYS"] = f"{ver}:{env_b64}"   # MASTER_KEYS is env-managed: operator must persist this
    return out


@router.get("/metrics")
def perf_metrics():
    return metrics.snapshot()


@router.get("/system")
def system():
    st = get_storage()
    from sqlalchemy import text
    from ..database import engine
    try:
        with engine.connect() as c: c.execute(text("select 1")); dbok = True
    except Exception: dbok = False
    return {"database": {"ok": dbok, "engine": engine.dialect.name}, "storage": {"backend": st.name, "ok": st.health()},
            "cache": {"backend": cache.backend()}, "audit": {"backend": audit.backend()},
            "email": {"mode": "smtp" if settings.SMTP_HOST else "dev-outbox"},
            "oauth": {"google": bool(settings.GOOGLE_CLIENT_ID), "github": bool(settings.GITHUB_CLIENT_ID)}, "env": settings.ENV}


@router.post("/reminders/run")
def run_reminders(db: Session = Depends(get_db)):
    return {"sent": send_expiry_reminders(db)}
