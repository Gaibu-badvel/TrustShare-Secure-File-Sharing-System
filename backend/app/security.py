"""Password hashing (bcrypt), JWT, TOTP MFA, secure token generation."""
import base64, hashlib, io, re, secrets, uuid
from datetime import timedelta
from typing import Optional

import bcrypt
import jwt
import pyotp

from .config import settings
from .database import utcnow
from datetime import timezone

# ---------- passwords ----------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode()[:72], bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, hashed: Optional[str]) -> bool:
    if not hashed:
        return False
    try:
        return bcrypt.checkpw(password.encode()[:72], hashed.encode())
    except ValueError:
        return False


def password_problems(pw: str) -> list[str]:
    errs = []
    if len(pw) < 8: errs.append("at least 8 characters")
    if not re.search(r"[a-z]", pw): errs.append("a lowercase letter")
    if not re.search(r"[A-Z]", pw): errs.append("an uppercase letter")
    if not re.search(r"\d", pw): errs.append("a digit")
    return errs


# ---------- secure tokens ----------
def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


# ---------- JWT ----------
def _encode(payload: dict, minutes: int = 0, days: int = 0) -> str:
    now = utcnow().replace(tzinfo=timezone.utc)
    payload = {**payload, "iat": now, "exp": now + timedelta(minutes=minutes, days=days), "jti": uuid.uuid4().hex}
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_access_token(user_id: str, role: str, session_id: str) -> str:
    return _encode({"sub": user_id, "role": role, "sid": session_id, "type": "access"}, minutes=settings.ACCESS_TOKEN_MINUTES)


def create_refresh_token(user_id: str, session_id: str) -> str:
    tok = jwt.encode({"sub": user_id, "type": "refresh", "jti": session_id,
                      "iat": utcnow().replace(tzinfo=timezone.utc),
                      "exp": utcnow().replace(tzinfo=timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_DAYS)},
                     settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return tok


def create_typed_token(kind: str, data: dict, minutes: int) -> str:
    return _encode({**data, "type": kind}, minutes=minutes)


def decode_token(token: str, expected_type: str) -> dict:
    """Raises jwt.PyJWTError on any problem."""
    data = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    if data.get("type") != expected_type:
        raise jwt.InvalidTokenError("wrong token type")
    return data


# ---------- TOTP MFA ----------
def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, email: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=settings.APP_NAME)


def verify_totp(secret: str, code: str) -> bool:
    code = (code or "").strip().replace(" ", "")
    return bool(code) and pyotp.TOTP(secret).verify(code, valid_window=1)


def qr_png_base64(data: str) -> str:
    import qrcode
    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


def new_backup_codes(n: int = 8) -> tuple[list[str], list[str]]:
    plain = [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}" for _ in range(n)]
    return plain, [sha256_hex(c) for c in plain]
