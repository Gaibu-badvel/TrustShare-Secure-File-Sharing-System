from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session
from .. import audit, services
from ..database import get_db
from ..deps import client_ip, get_current_user, require_writer
from ..models import File, Folder, ShareLink, FileShare, User
from ..schemas import FolderIn, FolderOut, FolderPatch

router = APIRouter(prefix="/api/folders", tags=["folders"])


def _own(db, fid, user) -> Folder:
    f = db.get(Folder, fid)
    if not f or f.owner_id != user.id: raise HTTPException(404, "Folder not found")
    return f


def _descendants(db, fid) -> list[str]:
    out, stack = [], [fid]
    while stack:
        cur = stack.pop(); out.append(cur)
        stack += [c for c in db.scalars(select(Folder.id).where(Folder.parent_id == cur))]
    return out


@router.get("", response_model=list[FolderOut])
def list_folders(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.scalars(select(Folder).where(Folder.owner_id == user.id).order_by(Folder.name)).all()


@router.post("", response_model=FolderOut, status_code=201)
def create_folder(body: FolderIn, request: Request, user: User = Depends(require_writer), db: Session = Depends(get_db)):
    if body.parent_id: _own(db, body.parent_id, user)
    dup = db.scalar(select(Folder).where(Folder.owner_id == user.id, Folder.parent_id == body.parent_id, Folder.name == body.name))
    if dup: raise HTTPException(409, "A folder with that name already exists here")
    f = Folder(owner_id=user.id, name=body.name.strip(), parent_id=body.parent_id)
    db.add(f); db.commit()
    audit.log(db, "folder.create", user.id, "folder", f.id, client_ip(request), name=f.name)
    return f


@router.patch("/{folder_id}", response_model=FolderOut)
def patch_folder(folder_id: str, body: FolderPatch, user: User = Depends(require_writer), db: Session = Depends(get_db)):
    f = _own(db, folder_id, user)
    if body.name: f.name = body.name.strip()
    if body.move_to_root: f.parent_id = None
    elif body.parent_id:
        _own(db, body.parent_id, user)
        if body.parent_id in _descendants(db, f.id): raise HTTPException(400, "Cannot move a folder into itself")
        f.parent_id = body.parent_id
    db.commit(); return f


@router.delete("/{folder_id}")
def delete_folder(folder_id: str, force: bool = False, request: Request = None, user: User = Depends(require_writer), db: Session = Depends(get_db)):
    f = _own(db, folder_id, user)
    ids = _descendants(db, f.id)
    files = db.scalars(select(File).where(File.folder_id.in_(ids))).all()
    if (files or len(ids) > 1) and not force:
        raise HTTPException(409, "Folder is not empty (use force=true to delete its contents)")
    for fl in files:
        services.delete_file_blobs(fl)
        for l in db.scalars(select(ShareLink).where(ShareLink.file_id == fl.id)): db.delete(l)
        for s in db.scalars(select(FileShare).where(FileShare.file_id == fl.id)): db.delete(s)
        db.delete(fl)
    db.flush()
    for fid in reversed(ids):
        db.delete(db.get(Folder, fid)); db.flush()
    db.commit()
    audit.log(db, "folder.delete", user.id, "folder", folder_id, client_ip(request) if request else "", files_removed=len(files))
    return {"ok": True, "files_removed": len(files)}
