import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordBearer
from sqlalchemy.orm import Session
from . import cache
from .database import get_db
from .models import User, AuthSession, File, FileShare
from .security import decode_token
from .database import utcnow

bearer = HTTPBearer(auto_error=False)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token", auto_error=False)


def client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    return (xff.split(",")[0].strip() if xff else (request.client.host if request.client else "")) or "unknown"


def _user_from_token(token: str, db: Session) -> User:
    try:
        data = decode_token(token, "access")
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token", {"WWW-Authenticate": "Bearer"})
    if cache.is_blacklisted(data["jti"]):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token revoked")
    sess = db.get(AuthSession, data.get("sid"))
    if not sess or sess.revoked or sess.expires_at < utcnow():
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session ended")
    user = db.get(User, data["sub"])
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Account disabled")
    return user


def get_current_user(token: str | None = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated", {"WWW-Authenticate": "Bearer"})
    return _user_from_token(token, db)


def get_optional_user(token: str | None = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User | None:
    if not token:
        return None
    try:
        return _user_from_token(token, db)
    except HTTPException:
        return None


def require_roles(*roles: str):
    def dep(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role")
        return user
    return dep


def require_writer(user: User = Depends(get_current_user)) -> User:
    if user.role == "viewer":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Viewer accounts are read-only")
    return user


require_admin = require_roles("admin")


def rate_limit(name: str, per_minute: int):
    def dep(request: Request):
        n = cache.incr(f"rl:{name}:{client_ip(request)}", 60)
        if n > per_minute:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many requests, slow down",
                                {"Retry-After": "60"})
    return dep


PERM_RANK = {"view": 1, "download": 2, "edit": 3, "owner": 4}


def file_access(db: Session, file_id: str, user: User, need: str = "view") -> tuple[File, str]:
    """Return (file, effective_permission) or raise 404/403. Owner and admin(owner-level read only via admin tools) rules."""
    f = db.get(File, file_id)
    if not f:
        raise HTTPException(404, "File not found")
    if f.owner_id == user.id:
        return f, "owner"
    sh = db.query(FileShare).filter(FileShare.file_id == file_id, FileShare.user_id == user.id).first()
    if not sh or (sh.expires_at and sh.expires_at < utcnow()):
        raise HTTPException(404, "File not found")  # don't leak existence
    if PERM_RANK[sh.permission] < PERM_RANK[need]:
        raise HTTPException(403, f"'{need}' permission required")
    return f, sh.permission
