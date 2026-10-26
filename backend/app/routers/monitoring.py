"""Access monitoring: audit logs, login activity, file access history, security events."""
from datetime import timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, desc
from sqlalchemy.orm import Session
from .. import audit
from ..database import get_db, utcnow
from ..deps import file_access, get_current_user
from ..models import DownloadEvent, LoginEvent, SecurityEvent, User

router = APIRouter(prefix="/api/monitor", tags=["monitoring"])


@router.get("/audit")
def audit_logs(action: str = "", severity: str = "", resource_id: str = "", hours: int = 24 * 30, scope: str = "me",
               limit: int = 100, skip: int = 0, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    actor = None if (scope == "all" and user.role == "admin") else user.id
    if scope == "all" and user.role != "admin": raise HTTPException(403, "Admin only")
    return {"backend": audit.backend(), "items": audit.query(db, actor, action or None, severity or None, resource_id or None,
                                                              utcnow() - timedelta(hours=hours), min(limit, 500), skip)}


@router.get("/logins")
def logins(scope: str = "me", limit: int = 50, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    q = select(LoginEvent)
    if scope == "all":
        if user.role != "admin": raise HTTPException(403, "Admin only")
    else:
        q = q.where(LoginEvent.user_id == user.id)
    rows = db.scalars(q.order_by(desc(LoginEvent.ts)).limit(min(limit, 500))).all()
    return [{"ts": r.ts, "email": r.email, "success": r.success, "method": r.method, "reason": r.reason, "ip": r.ip,
             "user_agent": r.user_agent} for r in rows]


@router.get("/downloads")
def downloads(limit: int = 50, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Recent access events on files I own."""
    from ..models import File
    rows = db.execute(select(DownloadEvent, File.name).join(File, File.id == DownloadEvent.file_id, isouter=True)
                      .where(DownloadEvent.owner_id == user.id).order_by(desc(DownloadEvent.ts)).limit(min(limit, 500))).all()
    return [{"ts": e.ts, "file_id": e.file_id, "file_name": n or "(deleted)", "kind": e.kind, "version": e.version, "ip": e.ip,
             "via_link": bool(e.link_id), "user_id": e.user_id} for e, n in rows]


@router.get("/files/{file_id}/access")
def file_access_history(file_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    f, _ = file_access(db, file_id, user, "owner")
    rows = db.scalars(select(DownloadEvent).where(DownloadEvent.file_id == f.id).order_by(desc(DownloadEvent.ts)).limit(200)).all()
    return [{"ts": e.ts, "kind": e.kind, "version": e.version, "ip": e.ip, "via_link": bool(e.link_id), "user_id": e.user_id} for e in rows]


@router.get("/security-events")
def security_events(scope: str = "me", only_open: bool = False, limit: int = 100, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    q = select(SecurityEvent)
    if scope == "all":
        if user.role != "admin": raise HTTPException(403, "Admin only")
    else:
        q = q.where(SecurityEvent.user_id == user.id)
    if only_open: q = q.where(SecurityEvent.resolved == False)  # noqa: E712
    rows = db.scalars(q.order_by(desc(SecurityEvent.ts)).limit(min(limit, 500))).all()
    return [{"id": r.id, "ts": r.ts, "type": r.type, "severity": r.severity, "message": r.message, "ip": r.ip,
             "resolved": r.resolved, "user_id": r.user_id} for r in rows]


@router.post("/security-events/{event_id}/resolve")
def resolve(event_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    e = db.get(SecurityEvent, event_id)
    if not e or (e.user_id != user.id and user.role != "admin"): raise HTTPException(404, "Event not found")
    e.resolved = True; db.commit(); return {"ok": True}
