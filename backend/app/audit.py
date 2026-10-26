"""Audit logging: MongoDB when configured/reachable, otherwise the SQL fallback table."""
from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy import select, desc, or_
from .config import settings
from .database import utcnow
from .models import AuditLogSQL

_mongo = None
_tried = False


def mongo():
    global _mongo, _tried
    if _tried:
        return _mongo
    _tried = True
    if settings.MONGO_URL:
        try:
            from pymongo import MongoClient
            c = MongoClient(settings.MONGO_URL, serverSelectionTimeoutMS=1500)
            c.admin.command("ping")
            col = c[settings.MONGO_DB]["audit_logs"]
            col.create_index("ts"); col.create_index("actor_id"); col.create_index("action")
            _mongo = col
        except Exception:
            _mongo = None
    return _mongo


def backend() -> str:
    return "mongodb" if mongo() is not None else "sql"


def log(db: Session, action: str, actor_id: Optional[str] = None, resource_type: str = "", resource_id: str = "",
        ip: str = "", severity: str = "info", owner_id: Optional[str] = None, **details):
    entry = dict(ts=utcnow(), actor_id=actor_id, owner_id=owner_id or actor_id, action=action, resource_type=resource_type,
                 resource_id=resource_id, ip=ip, severity=severity, details=details)
    col = mongo()
    if col is not None:
        try:
            col.insert_one(dict(entry)); return
        except Exception:
            pass
    db.add(AuditLogSQL(**entry)); db.commit()


def query(db: Session, actor_id: Optional[str] = None, action: Optional[str] = None, severity: Optional[str] = None,
          resource_id: Optional[str] = None, since: Optional[datetime] = None, limit: int = 100, skip: int = 0) -> list[dict]:
    col = mongo()
    if col is not None:
        f: dict = {}
        if actor_id: f["$or"] = [{"actor_id": actor_id}, {"owner_id": actor_id}]
        if action: f["action"] = {"$regex": f"^{action}"}
        if severity: f["severity"] = severity
        if resource_id: f["resource_id"] = resource_id
        if since: f["ts"] = {"$gte": since}
        rows = col.find(f).sort("ts", -1).skip(skip).limit(limit)
        return [{"id": str(r["_id"]), "ts": r["ts"], "actor_id": r.get("actor_id"), "action": r["action"],
                 "resource_type": r.get("resource_type", ""), "resource_id": r.get("resource_id", ""),
                 "ip": r.get("ip", ""), "severity": r.get("severity", "info"), "details": r.get("details", {})} for r in rows]
    q = select(AuditLogSQL)
    if actor_id: q = q.where(or_(AuditLogSQL.actor_id == actor_id, AuditLogSQL.owner_id == actor_id))
    if action: q = q.where(AuditLogSQL.action.like(f"{action}%"))
    if severity: q = q.where(AuditLogSQL.severity == severity)
    if resource_id: q = q.where(AuditLogSQL.resource_id == resource_id)
    if since: q = q.where(AuditLogSQL.ts >= since)
    rows = db.scalars(q.order_by(desc(AuditLogSQL.ts)).offset(skip).limit(limit)).all()
    return [{"id": r.id, "ts": r.ts, "actor_id": r.actor_id, "action": r.action, "resource_type": r.resource_type,
             "resource_id": r.resource_id, "ip": r.ip, "severity": r.severity, "details": r.details} for r in rows]


def count_since(db: Session, since: datetime, action_prefix: str = "") -> int:
    col = mongo()
    if col is not None:
        f = {"ts": {"$gte": since}}
        if action_prefix: f["action"] = {"$regex": f"^{action_prefix}"}
        return col.count_documents(f)
    from sqlalchemy import func
    q = select(func.count()).select_from(AuditLogSQL).where(AuditLogSQL.ts >= since)
    if action_prefix: q = q.where(AuditLogSQL.action.like(f"{action_prefix}%"))
    return db.scalar(q) or 0
