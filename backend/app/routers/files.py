"""File management: upload, categorise, search/filter, metadata, versions, download."""
from typing import Optional
from fastapi import APIRouter, Depends, File as FormFile, Form, HTTPException, Request, UploadFile
from sqlalchemy import select, or_, func, asc, desc
from sqlalchemy.orm import Session

from .. import audit, services
from ..database import get_db, utcnow
from ..deps import client_ip, file_access, get_current_user, rate_limit, require_writer
from ..models import File, FileShare, FileVersion, Folder, User
from ..schemas import FileOut, FilePatch, VersionOut

router = APIRouter(prefix="/api/files", tags=["files"], dependencies=[Depends(rate_limit("api", 600))])


def _out(f: File, perm: str, owner_name: str = "") -> FileOut:
    o = FileOut.model_validate(f); o.permission = perm; o.owner_name = owner_name; return o


@router.post("", response_model=FileOut, status_code=201)
async def upload(request: Request, file: UploadFile = FormFile(...), folder_id: Optional[str] = Form(None),
                 category: Optional[str] = Form(None), description: str = Form(""),
                 tags: str = Form(""), user: User = Depends(require_writer), db: Session = Depends(get_db)):
    name, data = await services.read_upload(file)
    if folder_id:
        fo = db.get(Folder, folder_id)
        if not fo or fo.owner_id != user.id: raise HTTPException(404, "Folder not found")
    cat = category if category in services.VALID_CATEGORIES else services.category_for(name)
    f = File(owner_id=user.id, folder_id=folder_id or None, name=name, category=cat, description=description[:2000],
             mime_type=file.content_type or "application/octet-stream",
             tags=[t.strip()[:32] for t in tags.split(",") if t.strip()][:10])
    db.add(f); db.flush()
    try:
        services.store_version(db, f, data, user, client_ip(request))
    except Exception:
        db.rollback(); raise
    audit.log(db, "file.upload", user.id, "file", f.id, client_ip(request), name=name, size=len(data))
    return _out(f, "owner")


@router.get("")
def list_files(q: str = "", category: str = "", folder_id: str = "", scope: str = "owned", sort: str = "created_at",
               order: str = "desc", page: int = 1, size: int = 50, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    size = max(1, min(size, 200)); page = max(1, page)
    shared_ids = select(FileShare.file_id).where(FileShare.user_id == user.id, or_(FileShare.expires_at.is_(None), FileShare.expires_at > utcnow()))
    if scope == "shared": cond = File.id.in_(shared_ids)
    elif scope == "all": cond = or_(File.owner_id == user.id, File.id.in_(shared_ids))
    else: cond = File.owner_id == user.id
    qry = select(File).where(cond)
    if q:
        like = f"%{q.lower()}%"
        qry = qry.where(or_(func.lower(File.name).like(like), func.lower(File.description).like(like), func.lower(File.mime_type).like(like)))
    if category: qry = qry.where(File.category == category)
    if folder_id == "root": qry = qry.where(File.folder_id.is_(None))
    elif folder_id: qry = qry.where(File.folder_id == folder_id)
    col = {"name": File.name, "size": File.size, "updated_at": File.updated_at}.get(sort, File.created_at)
    total = db.scalar(select(func.count()).select_from(qry.subquery())) or 0
    rows = db.scalars(qry.order_by(asc(col) if order == "asc" else desc(col)).offset((page - 1) * size).limit(size)).all()
    perms = {s.file_id: s.permission for s in db.scalars(select(FileShare).where(FileShare.user_id == user.id))}
    owners = {u.id: u.username for u in db.scalars(select(User).where(User.id.in_({r.owner_id for r in rows})))} if rows else {}
    return {"total": total, "page": page, "size": size,
            "items": [_out(f, "owner" if f.owner_id == user.id else perms.get(f.id, "view"), owners.get(f.owner_id, "")) for f in rows]}


@router.get("/{file_id}", response_model=FileOut)
def get_file(file_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    f, perm = file_access(db, file_id, user)
    return _out(f, perm, db.get(User, f.owner_id).username)


@router.patch("/{file_id}", response_model=FileOut)
def patch_file(file_id: str, body: FilePatch, request: Request, user: User = Depends(require_writer), db: Session = Depends(get_db)):
    f, perm = file_access(db, file_id, user, "edit")
    if perm != "owner" and (body.name or body.folder_id or body.move_to_root or body.category):
        raise HTTPException(403, "Only the owner can rename, move or recategorise")
    if body.name: f.name = services.clean_name(body.name)
    if body.category:
        if body.category not in services.VALID_CATEGORIES: raise HTTPException(400, "Unknown category")
        f.category = body.category
    if body.description is not None: f.description = body.description
    if body.tags is not None: f.tags = [t.strip()[:32] for t in body.tags if t.strip()][:10]
    if body.move_to_root: f.folder_id = None
    elif body.folder_id:
        fo = db.get(Folder, body.folder_id)
        if not fo or fo.owner_id != user.id: raise HTTPException(404, "Folder not found")
        f.folder_id = fo.id
    f.updated_at = utcnow(); db.commit()
    audit.log(db, "file.update", user.id, "file", f.id, client_ip(request))
    return _out(f, perm)


@router.delete("/{file_id}")
def delete_file(file_id: str, request: Request, user: User = Depends(require_writer), db: Session = Depends(get_db)):
    f, perm = file_access(db, file_id, user, "owner")
    services.delete_file_blobs(f)
    from ..models import ShareLink
    for l in db.scalars(select(ShareLink).where(ShareLink.file_id == f.id)): db.delete(l)
    for s in db.scalars(select(FileShare).where(FileShare.file_id == f.id)): db.delete(s)
    name = f.name; db.delete(f); db.commit()
    audit.log(db, "file.delete", user.id, "file", file_id, client_ip(request), name=name)
    return {"ok": True}


@router.get("/{file_id}/download")
def download(file_id: str, request: Request, version: Optional[int] = None, inline: bool = False,
             user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    f, perm = file_access(db, file_id, user, "view" if inline else "download")
    if version and perm not in ("owner", "edit"): raise HTTPException(403, "Only owners/editors can fetch old versions")
    fv = next((v for v in f.versions if v.version == (version or f.current_version)), None)
    if not fv: raise HTTPException(404, "Version not found")
    data = services.read_version(f, fv)
    services.track(db, f, fv, request, user, kind="view" if inline else "download")
    return services.file_response(f, data, inline=inline, version=fv.version)


@router.post("/{file_id}/versions", response_model=VersionOut, status_code=201)
async def new_version(file_id: str, request: Request, file: UploadFile = FormFile(...), user: User = Depends(require_writer),
                      db: Session = Depends(get_db)):
    f, perm = file_access(db, file_id, user, "edit")
    _, data = await services.read_upload(file)
    fv = services.store_version(db, f, data, user, client_ip(request))
    audit.log(db, "file.version.create", user.id, "file", f.id, client_ip(request), version=fv.version)
    return fv


@router.get("/{file_id}/versions", response_model=list[VersionOut])
def versions(file_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    f, _ = file_access(db, file_id, user)
    return sorted(f.versions, key=lambda v: -v.version)


@router.post("/{file_id}/versions/{version}/restore", response_model=VersionOut, status_code=201)
def restore_version(file_id: str, version: int, request: Request, user: User = Depends(require_writer), db: Session = Depends(get_db)):
    f, _ = file_access(db, file_id, user, "edit")
    old = next((v for v in f.versions if v.version == version), None)
    if not old: raise HTTPException(404, "Version not found")
    fv = services.store_version(db, f, services.read_version(f, old), user, client_ip(request))
    audit.log(db, "file.version.restore", user.id, "file", f.id, client_ip(request), restored=version, new_version=fv.version)
    return fv
