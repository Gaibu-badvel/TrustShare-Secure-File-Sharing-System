"""Analytics dashboards: file analytics (user) + security dashboard."""
from collections import Counter, defaultdict
from datetime import timedelta
from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from ..database import get_db, utcnow
from ..deps import get_current_user
from ..models import DownloadEvent, File, FileVersion, LoginEvent, SecurityEvent, ShareLink, FileShare, User
from .shares import link_status
from .. import services

router = APIRouter(prefix="/api/analytics", tags=["analytics"])


def _days(n: int):
    today = utcnow().date()
    return [(today - timedelta(days=i)).isoformat() for i in range(n - 1, -1, -1)]


@router.get("/files")
def file_analytics(days: int = 30, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    days = max(1, min(days, 365)); since = utcnow() - timedelta(days=days)
    files = db.scalars(select(File).where(File.owner_id == user.id)).all()
    used = services.used_bytes(db, user.id)
    by_cat = defaultdict(lambda: {"files": 0, "bytes": 0})
    for f in files:
        by_cat[f.category]["files"] += 1; by_cat[f.category]["bytes"] += f.size
    up = Counter(f.created_at.date().isoformat() for f in files if f.created_at >= since)
    ev = db.scalars(select(DownloadEvent).where(DownloadEvent.owner_id == user.id, DownloadEvent.ts >= since)).all()
    dl = Counter(e.ts.date().isoformat() for e in ev if e.kind == "download")
    vw = Counter(e.ts.date().isoformat() for e in ev if e.kind == "view")
    top = Counter(e.file_id for e in ev if e.kind == "download").most_common(5)
    names = {f.id: f.name for f in files}
    links = db.scalars(select(ShareLink).join(File, File.id == ShareLink.file_id).where(File.owner_id == user.id)).all()
    st = Counter(link_status(l) for l in links)
    direct = db.scalar(select(func.count()).select_from(FileShare).join(File, File.id == FileShare.file_id).where(File.owner_id == user.id)) or 0
    ds = _days(days)
    return {
        "storage": {"used_bytes": used, "quota_bytes": user.quota_bytes, "percent": round(used * 100 / user.quota_bytes, 2) if user.quota_bytes else 0,
                    "files": len(files), "versions": db.scalar(select(func.count()).select_from(FileVersion).join(File, File.id == FileVersion.file_id).where(File.owner_id == user.id)) or 0},
        "by_category": [{"category": k, **v} for k, v in sorted(by_cat.items())],
        "uploads_per_day": [{"date": d, "count": up.get(d, 0)} for d in ds],
        "downloads_per_day": [{"date": d, "downloads": dl.get(d, 0), "views": vw.get(d, 0)} for d in ds],
        "top_downloaded": [{"file_id": i, "name": names.get(i, "(deleted)"), "downloads": c} for i, c in top],
        "sharing": {"links_total": len(links), "links_active": st["active"], "links_expired": st["expired"], "links_revoked": st["revoked"],
                    "links_exhausted": st["exhausted"], "direct_shares": direct,
                    "total_link_downloads": sum(l.download_count for l in links)},
    }


@router.get("/security")
def security_dashboard(days: int = 30, scope: str = "me", user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    days = max(1, min(days, 365)); since = utcnow() - timedelta(days=days)
    allq = scope == "all" and user.role == "admin"
    lq = select(LoginEvent).where(LoginEvent.ts >= since)
    eq = select(SecurityEvent).where(SecurityEvent.ts >= since)
    if not allq:
        lq = lq.where(LoginEvent.user_id == user.id); eq = eq.where(SecurityEvent.user_id == user.id)
    logins = db.scalars(lq).all(); events = db.scalars(eq.order_by(SecurityEvent.ts.desc())).all()
    ok = Counter(l.ts.date().isoformat() for l in logins if l.success)
    bad = Counter(l.ts.date().isoformat() for l in logins if not l.success)
    ds = _days(days)
    return {
        "logins": {"success": sum(ok.values()), "failed": sum(bad.values()),
                   "per_day": [{"date": d, "success": ok.get(d, 0), "failed": bad.get(d, 0)} for d in ds]},
        "unauthorized_attempts": sum(bad.values()) + sum(1 for e in events if e.type in ("link_probing", "share_password_guessing")),
        "events_by_type": dict(Counter(e.type for e in events)),
        "events_by_severity": dict(Counter(e.severity for e in events)),
        "open_events": sum(1 for e in events if not e.resolved),
        "recent_events": [{"id": e.id, "ts": e.ts, "type": e.type, "severity": e.severity, "message": e.message, "ip": e.ip, "resolved": e.resolved} for e in events[:10]],
        "top_failed_ips": Counter(l.ip for l in logins if not l.success).most_common(5),
    }
