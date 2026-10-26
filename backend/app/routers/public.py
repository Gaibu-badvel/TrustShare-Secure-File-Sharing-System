"""Public (token-based) access to shared files. Files are decrypted in memory only for authorised requests."""
from typing import Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import update, or_
from sqlalchemy.orm import Session

from .. import audit, cache, monitor, services
from ..database import get_db, utcnow
from ..deps import client_ip, get_optional_user, rate_limit
from ..models import File, ShareLink, User
from ..notifications import notify
from ..security import sha256_hex, verify_password
from .shares import link_status

router = APIRouter(prefix="/api/public", tags=["public-links"], dependencies=[Depends(rate_limit("public", 60))])


def _load(db: Session, token: str, request: Request) -> tuple[ShareLink, File]:
    ip = client_ip(request)
    l = db.query(ShareLink).filter(ShareLink.token_hash == sha256_hex(token)).first()
    if not l:
        monitor.check_link_probing(db, ip)
        raise HTTPException(404, "Link not found")
    f = db.get(File, l.file_id)
    st = link_status(l)
    if st != "active" or not f:
        audit.log(db, "share.link.denied", None, "file", l.file_id, ip, severity="warning", owner_id=l.created_by, link_id=l.id, reason=st)
        monitor.check_link_probing(db, ip)
        if st == "expired" or st == "exhausted":
            notify(db, l.created_by, "access", "Blocked access to a share link", f"Someone tried to use a link that is {st}.", "/dashboard?tab=shared", email=False)
        raise HTTPException(410, f"This link is {st}")
    return l, f


def _guard(db: Session, l: ShareLink, request: Request, user: Optional[User], password: Optional[str]):
    ip = client_ip(request)
    if l.allowed_email:
        if not user or user.email.lower() != l.allowed_email:
            raise HTTPException(403, f"Sign in as {l.allowed_email} to access this link")
    if l.password_hash:
        key = f"linkpw:{l.id}:{ip}"
        if (int(cache.get(key) or 0)) >= 5:
            raise HTTPException(429, "Too many wrong passwords. Try again later.")
        if not password or not verify_password(password, l.password_hash):
            n = cache.incr(key, 600)
            audit.log(db, "share.link.bad_password", None, "file", l.file_id, ip, severity="warning", owner_id=l.created_by, link_id=l.id)
            if n == 5:
                monitor.security_event(db, "share_password_guessing", "Repeated wrong passwords on a protected share link.", "high", l.created_by, ip)
            raise HTTPException(401, "Password required or incorrect")


@router.get("/links/{token}")
def link_meta(token: str, request: Request, db: Session = Depends(get_db)):
    l, f = _load(db, token, request)
    return {"file_name": f.name, "size": f.size, "category": f.category, "mime_type": f.mime_type, "permission": l.permission,
            "requires_password": bool(l.password_hash), "requires_login_as": l.allowed_email, "expires_at": l.expires_at,
            "remaining_downloads": None if l.max_downloads is None else max(0, l.max_downloads - l.download_count),
            "note": l.note, "status": link_status(l)}


@router.get("/links/{token}/preview")
def link_preview(token: str, request: Request, x_share_password: Optional[str] = Header(None), db: Session = Depends(get_db),
                 user: Optional[User] = Depends(get_optional_user)):
    l, f = _load(db, token, request); _guard(db, l, request, user, x_share_password)
    fv = next(v for v in f.versions if v.version == f.current_version)
    data = services.read_version(f, fv)
    db.execute(update(ShareLink).where(ShareLink.id == l.id).values(view_count=ShareLink.view_count + 1)); db.commit()
    services.track(db, f, fv, request, user, l.id, "view")
    return services.file_response(f, data, inline=True)


@router.get("/links/{token}/download")
def link_download(token: str, request: Request, x_share_password: Optional[str] = Header(None), db: Session = Depends(get_db),
                  user: Optional[User] = Depends(get_optional_user)):
    l, f = _load(db, token, request)
    if l.permission != "download": raise HTTPException(403, "This link is view-only")
    _guard(db, l, request, user, x_share_password)
    # atomic download-limit enforcement (race-safe)
    res = db.execute(update(ShareLink).where(ShareLink.id == l.id, ShareLink.revoked == False,  # noqa: E712
                                             or_(ShareLink.max_downloads.is_(None), ShareLink.download_count < ShareLink.max_downloads))
                     .values(download_count=ShareLink.download_count + 1))
    db.commit()
    if res.rowcount == 0: raise HTTPException(410, "This link has reached its download limit")
    fv = next(v for v in f.versions if v.version == f.current_version)
    data = services.read_version(f, fv)
    services.track(db, f, fv, request, user, l.id, "download")
    return services.file_response(f, data)
