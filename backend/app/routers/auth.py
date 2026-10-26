"""Authentication: register/login, JWT + refresh rotation, MFA (TOTP), password recovery, sessions."""
from datetime import timedelta
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from .. import audit, cache, monitor
from ..config import settings
from ..database import get_db, utcnow
from ..deps import client_ip, get_current_user, rate_limit, oauth2_scheme
from ..mailer import send_email
from ..models import AuthSession, PasswordReset, User
from ..notifications import notify
from ..schemas import *  # noqa
from ..security import (create_access_token, create_refresh_token, create_typed_token, decode_token, hash_password,
                        new_backup_codes, new_token, new_totp_secret, qr_png_base64, sha256_hex, totp_uri,
                        verify_password, verify_totp)

router = APIRouter(prefix="/api/auth", tags=["auth"], dependencies=[Depends(rate_limit("auth", settings.AUTH_RATE_LIMIT_PER_MINUTE))])


def issue_tokens(db: Session, user: User, request: Request, method: str = "password") -> dict:
    ip = client_ip(request); ua = request.headers.get("user-agent", "")[:255]
    sess = AuthSession(user_id=user.id, ip=ip, user_agent=ua, expires_at=utcnow() + timedelta(days=settings.REFRESH_TOKEN_DAYS))
    db.add(sess)
    user.failed_attempts = 0; user.locked_until = None
    prev_ip = user.last_login_ip
    monitor.record_login(db, user.email, True, ip, ua, user, method)
    user.last_login_at = utcnow(); user.last_login_ip = ip
    db.commit()
    return {"access_token": create_access_token(user.id, user.role, sess.id),
            "refresh_token": create_refresh_token(user.id, sess.id), "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_MINUTES * 60, "user": UserOut.model_validate(user).model_dump(mode="json")}


@router.post("/register", response_model=UserOut, status_code=201)
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)):
    email = body.email.lower()
    if db.scalar(select(User).where(func.lower(User.email) == email)):
        raise HTTPException(409, "Email already registered")
    if db.scalar(select(User).where(func.lower(User.username) == body.username.lower())):
        raise HTTPException(409, "Username already taken")
    first = (db.scalar(select(func.count()).select_from(User)) or 0) == 0
    is_admin = first or (settings.ADMIN_EMAIL and email == settings.ADMIN_EMAIL.lower())
    user = User(email=email, username=body.username, full_name=body.full_name, password_hash=hash_password(body.password),
                role="admin" if is_admin else "user", quota_bytes=settings.DEFAULT_QUOTA_MB * 1024 * 1024)
    db.add(user); db.commit()
    audit.log(db, "auth.register", user.id, "user", user.id, client_ip(request), role=user.role)
    notify(db, user, "system", "Welcome to TrustShare", "Your account is ready. Enable multi-factor authentication in Settings for extra protection.", "/dashboard?tab=settings", email=False)
    return user


def _fail(db, request, email, user, reason):
    monitor.record_login(db, email, False, client_ip(request), request.headers.get("user-agent", ""), user, reason=reason)
    raise HTTPException(401, "Invalid email or password")


def _check_password_login(db: Session, request: Request, email: str, password: str) -> User:
    user = db.scalar(select(User).where(func.lower(User.email) == email.lower()))
    if user and user.locked_until and user.locked_until > utcnow():
        mins = int((user.locked_until - utcnow()).total_seconds() // 60) + 1
        monitor.record_login(db, email, False, client_ip(request), request.headers.get("user-agent", ""), user, reason="locked")
        raise HTTPException(423, f"Account temporarily locked. Try again in {mins} minute(s).")
    if not user or not verify_password(password, user.password_hash):
        if user:
            user.failed_attempts += 1
            if user.failed_attempts >= settings.MAX_FAILED_LOGINS:
                user.locked_until = utcnow() + timedelta(minutes=settings.LOCKOUT_MINUTES)
                db.commit()
                monitor.security_event(db, "account_locked", f"Account locked after {user.failed_attempts} failed attempts.",
                                       "high", user.id, client_ip(request))
            db.commit()
        _fail(db, request, email, user, "bad_credentials")
    if not user.is_active:
        _fail(db, request, email, user, "disabled")
    return user


@router.post("/login")
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    user = _check_password_login(db, request, body.email, body.password)
    if user.mfa_enabled:
        return {"mfa_required": True, "mfa_token": create_typed_token("mfa", {"sub": user.id}, settings.MFA_TOKEN_MINUTES)}
    return issue_tokens(db, user, request)


def _consume_code(user: User, code: str, db: Session) -> bool:
    if verify_totp(user.mfa_secret or "", code):
        return True
    h = sha256_hex(code.strip().lower())
    if user.mfa_backup_codes and h in user.mfa_backup_codes:  # one-time backup code
        user.mfa_backup_codes = [c for c in user.mfa_backup_codes if c != h]; db.commit()
        return True
    return False


@router.post("/mfa/verify")
def mfa_verify(body: MfaVerifyIn, request: Request, db: Session = Depends(get_db)):
    try:
        data = decode_token(body.mfa_token, "mfa")
    except jwt.PyJWTError:
        raise HTTPException(401, "MFA session expired, sign in again")
    user = db.get(User, data["sub"])
    if not user or not user.mfa_enabled:
        raise HTTPException(401, "Invalid MFA session")
    n = cache.incr(f"mfa:{user.id}", 300)
    if n > 5:
        raise HTTPException(429, "Too many invalid codes; wait a few minutes")
    if not _consume_code(user, body.code, db):
        monitor.record_login(db, user.email, False, client_ip(request), request.headers.get("user-agent", ""), user, "mfa", "bad_mfa_code")
        raise HTTPException(401, "Invalid verification code")
    cache.delete(f"mfa:{user.id}")
    return issue_tokens(db, user, request, "mfa")


@router.post("/token", include_in_schema=True, summary="OAuth2 password flow (Swagger 'Authorize'); put TOTP in client_secret if MFA is on")
def token_form(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = _check_password_login(db, request, form.username, form.password)
    if user.mfa_enabled and not _consume_code(user, form.client_secret or "", db):
        raise HTTPException(401, "MFA code required (send it as client_secret)")
    t = issue_tokens(db, user, request, "mfa" if user.mfa_enabled else "password")
    return {k: t[k] for k in ("access_token", "refresh_token", "token_type")}


@router.post("/refresh")
def refresh(body: RefreshIn, request: Request, db: Session = Depends(get_db)):
    try:
        data = decode_token(body.refresh_token, "refresh")
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid refresh token")
    sess = db.get(AuthSession, data["jti"])
    if not sess or sess.revoked or sess.expires_at < utcnow():
        # reuse of a rotated/revoked token => possible theft: kill every session of that user
        if sess and sess.revoked:
            for s in db.scalars(select(AuthSession).where(AuthSession.user_id == sess.user_id, AuthSession.revoked == False)):  # noqa: E712
                s.revoked = True
            db.commit()
            monitor.security_event(db, "refresh_token_reuse", "A revoked refresh token was reused; all sessions were ended.",
                                   "high", sess.user_id, client_ip(request))
        raise HTTPException(401, "Session expired")
    user = db.get(User, sess.user_id)
    if not user or not user.is_active:
        raise HTTPException(401, "Account disabled")
    sess.revoked = True  # rotation
    new = AuthSession(user_id=user.id, ip=client_ip(request), user_agent=request.headers.get("user-agent", "")[:255],
                      expires_at=utcnow() + timedelta(days=settings.REFRESH_TOKEN_DAYS))
    db.add(new); db.commit()
    return {"access_token": create_access_token(user.id, user.role, new.id), "refresh_token": create_refresh_token(user.id, new.id),
            "token_type": "bearer", "expires_in": settings.ACCESS_TOKEN_MINUTES * 60}


@router.post("/logout")
def logout(request: Request, token: str = Depends(oauth2_scheme), user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    data = decode_token(token, "access")
    sess = db.get(AuthSession, data["sid"])
    if sess: sess.revoked = True; db.commit()
    cache.blacklist_token(data["jti"], settings.ACCESS_TOKEN_MINUTES * 60 + 5)
    audit.log(db, "auth.logout", user.id, "user", user.id, client_ip(request))
    return {"ok": True}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user


@router.patch("/me", response_model=UserOut)
def update_me(body: ProfileIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if body.full_name is not None: user.full_name = body.full_name
    if body.notify_email is not None: user.notify_email = body.notify_email
    db.commit(); return user


@router.get("/sessions")
def sessions(user: User = Depends(get_current_user), token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    cur = decode_token(token, "access")["sid"]
    rows = db.scalars(select(AuthSession).where(AuthSession.user_id == user.id, AuthSession.revoked == False,  # noqa: E712
                                                AuthSession.expires_at > utcnow()).order_by(AuthSession.created_at.desc())).all()
    return [{"id": s.id, "ip": s.ip, "user_agent": s.user_agent, "created_at": s.created_at, "current": s.id == cur} for s in rows]


@router.delete("/sessions/{sid}")
def revoke_session(sid: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    s = db.get(AuthSession, sid)
    if not s or s.user_id != user.id: raise HTTPException(404, "Session not found")
    s.revoked = True; db.commit(); return {"ok": True}


@router.post("/logout-all")
def logout_all(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    for s in db.scalars(select(AuthSession).where(AuthSession.user_id == user.id, AuthSession.revoked == False)):  # noqa: E712
        s.revoked = True
    db.commit(); return {"ok": True}


# ---------------- MFA management ----------------
@router.post("/mfa/setup")
def mfa_setup(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.mfa_enabled: raise HTTPException(400, "MFA already enabled")
    user.mfa_secret = new_totp_secret(); db.commit()
    uri = totp_uri(user.mfa_secret, user.email)
    return {"secret": user.mfa_secret, "otpauth_uri": uri, "qr_png_base64": qr_png_base64(uri)}


@router.post("/mfa/enable")
def mfa_enable(body: MfaCodeIn, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.mfa_enabled: raise HTTPException(400, "MFA already enabled")
    if not user.mfa_secret or not verify_totp(user.mfa_secret, body.code):
        raise HTTPException(400, "Invalid code")
    plain, hashed = new_backup_codes()
    user.mfa_enabled = True; user.mfa_backup_codes = hashed; db.commit()
    audit.log(db, "auth.mfa.enabled", user.id, "user", user.id, client_ip(request))
    return {"enabled": True, "backup_codes": plain}


@router.post("/mfa/disable")
def mfa_disable(body: MfaDisableIn, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not user.mfa_enabled: raise HTTPException(400, "MFA is not enabled")
    if user.password_hash and not verify_password(body.password, user.password_hash):
        raise HTTPException(400, "Wrong password")
    if not _consume_code(user, body.code, db): raise HTTPException(400, "Invalid code")
    user.mfa_enabled = False; user.mfa_secret = None; user.mfa_backup_codes = None; db.commit()
    audit.log(db, "auth.mfa.disabled", user.id, "user", user.id, client_ip(request), severity="warning")
    monitor.security_event(db, "mfa_disabled", "Multi-factor authentication was turned off.", "medium", user.id, client_ip(request))
    return {"enabled": False}


# ---------------- password recovery / change ----------------
@router.post("/forgot-password")
def forgot_password(body: ForgotIn, request: Request, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(func.lower(User.email) == body.email.lower()))
    if user and user.is_active:
        raw = new_token(32)
        db.add(PasswordReset(user_id=user.id, token_hash=sha256_hex(raw),
                             expires_at=utcnow() + timedelta(minutes=settings.RESET_TOKEN_MINUTES)))
        db.commit()
        link = f"{settings.FRONTEND_URL}/reset-password?token={raw}"
        send_email(user.email, "Reset your TrustShare password",
                   f"Use the link below to choose a new password (valid {settings.RESET_TOKEN_MINUTES} minutes):\n\n{link}\n\n"
                   "If you didn't request this, ignore this email.")
        audit.log(db, "auth.password.reset_requested", user.id, "user", user.id, client_ip(request))
    return {"message": "If that email is registered, a reset link has been sent."}  # no user enumeration


@router.post("/reset-password")
def reset_password(body: ResetIn, request: Request, db: Session = Depends(get_db)):
    pr = db.scalar(select(PasswordReset).where(PasswordReset.token_hash == sha256_hex(body.token)))
    if not pr or pr.used or pr.expires_at < utcnow():
        raise HTTPException(400, "Reset link is invalid or has expired")
    user = db.get(User, pr.user_id)
    user.password_hash = hash_password(body.new_password); user.failed_attempts = 0; user.locked_until = None
    pr.used = True
    for s in db.scalars(select(AuthSession).where(AuthSession.user_id == user.id, AuthSession.revoked == False)):  # noqa: E712
        s.revoked = True
    db.commit()
    audit.log(db, "auth.password.reset", user.id, "user", user.id, client_ip(request), severity="warning")
    notify(db, user, "security", "Your password was changed", "If this wasn't you, contact an administrator immediately.", "/dashboard?tab=security")
    return {"message": "Password updated. Please sign in."}


@router.post("/change-password")
def change_password(body: ChangePasswordIn, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(400, "Current password is incorrect")
    user.password_hash = hash_password(body.new_password); db.commit()
    audit.log(db, "auth.password.changed", user.id, "user", user.id, client_ip(request))
    return {"ok": True}
