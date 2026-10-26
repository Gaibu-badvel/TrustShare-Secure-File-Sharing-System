"""Shared file services: validation, encrypted store/retrieve, download tracking."""
import mimetypes, os, re, uuid
from typing import Optional
from urllib.parse import quote
from fastapi import HTTPException, Request, UploadFile
from fastapi.responses import Response
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from . import audit, crypto, metrics, monitor
from .config import settings
from .database import utcnow
from .deps import client_ip
from .models import DownloadEvent, File, FileVersion, User
from .notifications import notify
from .storage import get_storage

CATEGORIES = {
    "documents": {"pdf", "doc", "docx", "txt", "rtf", "odt", "md", "ppt", "pptx", "xls", "xlsx", "csv", "odp", "ods", "json", "xml"},
    "images": {"png", "jpg", "jpeg", "gif", "webp", "svg", "bmp", "tiff", "heic"},
    "video": {"mp4", "mov", "avi", "mkv", "webm"},
    "audio": {"mp3", "wav", "ogg", "flac", "m4a"},
    "archives": {"zip", "tar", "gz", "7z", "rar", "bz2"},
    "code": {"py", "js", "ts", "tsx", "jsx", "java", "c", "cpp", "go", "rs", "html", "css", "sql", "yml", "yaml", "sh", "ipynb"},
}
ALLOWED_EXT = set().union(*CATEGORIES.values())
VALID_CATEGORIES = set(CATEGORIES) | {"other"}
BLOCKED_MAGIC = (b"MZ", b"\x7fELF", b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe")  # Windows/Linux/macOS executables
INLINE_OK = {"image/png", "image/jpeg", "image/gif", "image/webp", "application/pdf", "text/plain"}


def category_for(name: str) -> str:
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return next((c for c, exts in CATEGORIES.items() if ext in exts), "other")


def clean_name(name: str) -> str:
    name = os.path.basename((name or "file").replace("\\", "/"))
    name = re.sub(r"[\x00-\x1f<>:\"|?*]", "_", name).strip(". ") or "file"
    return name[:255]


async def read_upload(upload: UploadFile) -> tuple[str, bytes]:
    """Validate type/size and return (clean_name, bytes). Raises 400/413/415."""
    name = clean_name(upload.filename or "")
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in ALLOWED_EXT:
        raise HTTPException(415, f"File type '.{ext}' is not allowed")
    limit = settings.MAX_UPLOAD_MB * 1024 * 1024
    chunks, total = [], 0
    while True:
        chunk = await upload.read(1024 * 1024)
        if not chunk: break
        total += len(chunk)
        if total > limit: raise HTTPException(413, f"File exceeds {settings.MAX_UPLOAD_MB} MB limit")
        chunks.append(chunk)
    data = b"".join(chunks)
    if not data: raise HTTPException(400, "Empty file")
    if data.startswith(BLOCKED_MAGIC): raise HTTPException(415, "Executable content is not allowed")
    return name, data


def used_bytes(db: Session, owner_id: str) -> int:
    return db.scalar(select(func.coalesce(func.sum(FileVersion.size), 0)).join(File, File.id == FileVersion.file_id)
                     .where(File.owner_id == owner_id)) or 0


def store_version(db: Session, f: File, data: bytes, user: User, ip: str) -> FileVersion:
    owner = db.get(User, f.owner_id)
    if used_bytes(db, owner.id) + len(data) > owner.quota_bytes:
        raise HTTPException(413, "Storage quota exceeded")
    ver = (max((v.version for v in f.versions), default=0)) + 1
    with metrics.timer("encrypt"):
        blob, wrapped, kv, sha = crypto.encrypt_bytes(data, aad=f"{f.id}:{ver}".encode())
    key = f"{f.owner_id}/{f.id}/v{ver}-{uuid.uuid4().hex[:8]}.enc"
    with metrics.timer("storage_put"):
        get_storage().put(key, blob)
    fv = FileVersion(file_id=f.id, version=ver, storage_key=key, size=len(data), sha256=sha, wrapped_key=wrapped,
                     key_version=kv, uploaded_by=user.id)
    db.add(fv)
    f.current_version, f.size, f.updated_at = ver, len(data), utcnow()
    db.commit()
    metrics.count("uploads"); metrics.count("bytes_encrypted", len(data))
    return fv


def read_version(f: File, fv: FileVersion) -> bytes:
    with metrics.timer("storage_get"):
        blob = get_storage().get(fv.storage_key)
    try:
        with metrics.timer("decrypt"):
            data = crypto.decrypt_bytes(blob, fv.wrapped_key, fv.key_version, aad=f"{f.id}:{fv.version}".encode())
    except Exception:
        raise HTTPException(500, "Integrity check failed: stored data was tampered with or key is unavailable")
    import hashlib
    if hashlib.sha256(data).hexdigest() != fv.sha256:
        raise HTTPException(500, "Integrity check failed (hash mismatch)")
    metrics.count("bytes_decrypted", len(data))
    return data


def delete_file_blobs(f: File):
    st = get_storage()
    for v in f.versions:
        try: st.delete(v.storage_key)
        except Exception: pass


def file_response(f: File, data: bytes, inline: bool = False, version: Optional[int] = None) -> Response:
    mime = f.mime_type or mimetypes.guess_type(f.name)[0] or "application/octet-stream"
    inline = inline and mime in INLINE_OK
    disp = "inline" if inline else "attachment"
    return Response(content=data, media_type=mime if inline else "application/octet-stream", headers={
        "Content-Disposition": f"{disp}; filename*=UTF-8''{quote(f.name)}",
        "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
        "Content-Security-Policy": "default-src 'none'; sandbox",
        "X-TrustShare-Version": str(version or f.current_version)})


def track(db: Session, f: File, fv: FileVersion, request: Request, user: Optional[User], link_id: Optional[str] = None,
          kind: str = "download"):
    ip = client_ip(request)
    db.add(DownloadEvent(file_id=f.id, owner_id=f.owner_id, version=fv.version, user_id=user.id if user else None,
                         link_id=link_id, kind=kind, ip=ip, user_agent=request.headers.get("user-agent", "")[:255], bytes=fv.size))
    db.commit()
    audit.log(db, f"file.{kind}", user.id if user else None, "file", f.id, ip, owner_id=f.owner_id, name=f.name, version=fv.version, via_link=bool(link_id))
    monitor.check_download_spike(db, f.owner_id, user.id if user else None, ip)
    if not user or user.id != f.owner_id:
        who = user.username if user else "an anonymous visitor (share link)"
        notify(db, f.owner_id, "download" if kind == "download" else "access",
               f"{'Downloaded' if kind == 'download' else 'Viewed'}: {f.name}", f"{who} {kind}ed \"{f.name}\" from {ip}.",
               "/dashboard?tab=activity", email=(kind == "download"))
