"""Secure sharing (owner side): temporary links, per-user shares, permissions, share activity."""
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from .. import audit
from ..config import settings
from ..database import get_db, utcnow
from ..deps import client_ip, file_access, get_current_user, require_writer
from ..models import DownloadEvent, File, FileShare, ShareLink, User
from ..notifications import notify
from ..schemas import LinkIn, LinkOut, ShareIn, ShareOut
from ..security import hash_password, new_token, sha256_hex

router = APIRouter(prefix="/api", tags=["sharing"])


def link_status(l: ShareLink) -> str:
    if l.revoked: return "revoked"
    if l.expires_at and l.expires_at < utcnow(): return "expired"
    if l.max_downloads is not None and l.download_count >= l.max_downloads: return "exhausted"
    return "active"


def link_out(l: ShareLink, token: str | None = None) -> LinkOut:
    o = LinkOut.model_validate(l)
    o.has_password = bool(l.password_hash); o.status = link_status(l)
    if token: o.token = token; o.url = f"{settings.FRONTEND_URL}/s/{token}"
    return o


@router.post("/files/{file_id}/links", response_model=LinkOut, status_code=201)
def create_link(file_id: str, body: LinkIn, request: Request, user: User = Depends(require_writer), db: Session = Depends(get_db)):
    f, _ = file_access(db, file_id, user, "owner")
    token = new_token(32)
    l = ShareLink(file_id=f.id, token_hash=sha256_hex(token), token_hint=token[:4], permission=body.permission,
                  expires_at=utcnow() + timedelta(hours=body.expires_in_hours) if body.expires_in_hours else None,
                  max_downloads=body.max_downloads, password_hash=hash_password(body.password) if body.password else None,
                  allowed_email=body.allowed_email.lower() if body.allowed_email else None, note=body.note, created_by=user.id)
    db.add(l); db.commit()
    audit.log(db, "share.link.create", user.id, "file", f.id, client_ip(request), link_id=l.id, permission=l.permission,
              expires_at=str(l.expires_at), max_downloads=l.max_downloads)
    if l.allowed_email:
        target = db.scalar(select(User).where(func.lower(User.email) == l.allowed_email))
        if target:
            notify(db, target, "share", f"{user.username} shared \"{f.name}\" with you", "Open the secure link you received.", "/dashboard?tab=shared")
    return link_out(l, token)  # raw token is returned exactly once


@router.get("/files/{file_id}/links", response_model=list[LinkOut])
def file_links(file_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    f, _ = file_access(db, file_id, user, "owner")
    return [link_out(l) for l in db.scalars(select(ShareLink).where(ShareLink.file_id == f.id).order_by(ShareLink.created_at.desc()))]


@router.get("/links")
def my_links(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    rows = db.execute(select(ShareLink, File.name).join(File, File.id == ShareLink.file_id)
                      .where(File.owner_id == user.id).order_by(ShareLink.created_at.desc()).limit(200)).all()
    return [{**link_out(l).model_dump(mode="json"), "file_name": n} for l, n in rows]


def _own_link(db, link_id, user) -> ShareLink:
    l = db.get(ShareLink, link_id)
    if not l or db.get(File, l.file_id).owner_id != user.id: raise HTTPException(404, "Link not found")
    return l


@router.delete("/links/{link_id}")
def revoke_link(link_id: str, request: Request, user: User = Depends(require_writer), db: Session = Depends(get_db)):
    l = _own_link(db, link_id, user); l.revoked = True; db.commit()
    audit.log(db, "share.link.revoke", user.id, "file", l.file_id, client_ip(request), link_id=l.id)
    return {"ok": True}


@router.get("/links/{link_id}/activity")
def link_activity(link_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    l = _own_link(db, link_id, user)
    rows = db.scalars(select(DownloadEvent).where(DownloadEvent.link_id == l.id).order_by(DownloadEvent.ts.desc()).limit(200)).all()
    return [{"ts": r.ts, "kind": r.kind, "ip": r.ip, "user_agent": r.user_agent, "user_id": r.user_id} for r in rows]


# ---------- per-user shares ----------
@router.post("/files/{file_id}/shares", response_model=ShareOut, status_code=201)
def share_with_user(file_id: str, body: ShareIn, request: Request, user: User = Depends(require_writer), db: Session = Depends(get_db)):
    f, _ = file_access(db, file_id, user, "owner")
    target = db.scalar(select(User).where(func.lower(User.email) == body.email.lower(), User.is_active == True))  # noqa: E712
    if not target: raise HTTPException(404, "No registered user with that email")
    if target.id == user.id: raise HTTPException(400, "You already own this file")
    exp = utcnow() + timedelta(hours=body.expires_in_hours) if body.expires_in_hours else None
    s = db.scalar(select(FileShare).where(FileShare.file_id == f.id, FileShare.user_id == target.id))
    if s: s.permission, s.expires_at = body.permission, exp
    else:
        s = FileShare(file_id=f.id, user_id=target.id, permission=body.permission, expires_at=exp, created_by=user.id); db.add(s)
    db.commit()
    audit.log(db, "share.user.grant", user.id, "file", f.id, client_ip(request), target=target.id, permission=body.permission)
    notify(db, target, "share", f"{user.username} shared \"{f.name}\" with you",
           f"Access level: {body.permission}." + (f" Expires {exp:%Y-%m-%d %H:%M} UTC." if exp else ""), "/dashboard?tab=shared")
    return ShareOut(id=s.id, user_id=target.id, email=target.email, username=target.username, permission=s.permission,
                    expires_at=s.expires_at, created_at=s.created_at)


@router.get("/files/{file_id}/shares", response_model=list[ShareOut])
def list_shares(file_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    f, _ = file_access(db, file_id, user, "owner")
    rows = db.execute(select(FileShare, User).join(User, User.id == FileShare.user_id).where(FileShare.file_id == f.id)).all()
    return [ShareOut(id=s.id, user_id=u.id, email=u.email, username=u.username, permission=s.permission,
                     expires_at=s.expires_at, created_at=s.created_at) for s, u in rows]


@router.delete("/shares/{share_id}")
def remove_share(share_id: str, request: Request, user: User = Depends(require_writer), db: Session = Depends(get_db)):
    s = db.get(FileShare, share_id)
    if not s or db.get(File, s.file_id).owner_id != user.id: raise HTTPException(404, "Share not found")
    audit.log(db, "share.user.revoke", user.id, "file", s.file_id, client_ip(request), target=s.user_id)
    db.delete(s); db.commit(); return {"ok": True}
