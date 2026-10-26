"""OAuth2 authorization-code login (Google, GitHub). Enabled when client id/secret are configured."""
from urllib.parse import urlencode
import httpx, jwt
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from .. import audit
from ..config import settings
from ..database import get_db
from ..deps import client_ip
from ..models import User
from ..security import create_typed_token, decode_token, hash_password, new_token
from .auth import issue_tokens

router = APIRouter(prefix="/api/auth/oauth", tags=["oauth2"])

PROVIDERS = {
    "google": dict(auth="https://accounts.google.com/o/oauth2/v2/auth", token="https://oauth2.googleapis.com/token",
                   userinfo="https://openidconnect.googleapis.com/v1/userinfo", scope="openid email profile",
                   id=lambda: settings.GOOGLE_CLIENT_ID, secret=lambda: settings.GOOGLE_CLIENT_SECRET),
    "github": dict(auth="https://github.com/login/oauth/authorize", token="https://github.com/login/oauth/access_token",
                   userinfo="https://api.github.com/user", scope="read:user user:email",
                   id=lambda: settings.GITHUB_CLIENT_ID, secret=lambda: settings.GITHUB_CLIENT_SECRET),
}


def _cfg(name: str) -> dict:
    p = PROVIDERS.get(name)
    if not p: raise HTTPException(404, "Unknown provider")
    if not p["id"]() or not p["secret"](): raise HTTPException(501, f"{name} OAuth is not configured on this server")
    return p


def _redirect_uri(name: str) -> str:
    return f"{settings.BACKEND_URL}/api/auth/oauth/{name}/callback"


def fetch_profile(name: str, code: str) -> dict:
    """Exchange code for token and return {sub, email, name}. Separate function so tests can mock it."""
    p = _cfg(name)
    with httpx.Client(timeout=10) as c:
        tr = c.post(p["token"], data={"client_id": p["id"](), "client_secret": p["secret"](), "code": code,
                                      "redirect_uri": _redirect_uri(name), "grant_type": "authorization_code"},
                    headers={"Accept": "application/json"})
        tr.raise_for_status()
        at = tr.json().get("access_token")
        if not at: raise HTTPException(400, "OAuth token exchange failed")
        h = {"Authorization": f"Bearer {at}", "Accept": "application/json"}
        info = c.get(p["userinfo"], headers=h).json()
        if name == "github":
            email = info.get("email")
            if not email:
                emails = c.get("https://api.github.com/user/emails", headers=h).json()
                email = next((e["email"] for e in emails if e.get("primary") and e.get("verified")), None)
            return {"sub": str(info["id"]), "email": email, "name": info.get("name") or info.get("login", "")}
        if not info.get("email_verified", True): raise HTTPException(400, "Provider email not verified")
        return {"sub": info["sub"], "email": info.get("email"), "name": info.get("name", "")}


@router.get("/providers")
def providers():
    return {n: bool(p["id"]() and p["secret"]()) for n, p in PROVIDERS.items()}


@router.get("/{provider}/login")
def oauth_login(provider: str):
    p = _cfg(provider)
    state = create_typed_token("oauth_state", {"p": provider}, 10)
    q = urlencode({"client_id": p["id"](), "redirect_uri": _redirect_uri(provider), "response_type": "code",
                   "scope": p["scope"], "state": state})
    return RedirectResponse(f"{p['auth']}?{q}")


@router.get("/{provider}/callback")
def oauth_callback(provider: str, request: Request, code: str = "", state: str = "", error: str = "", db: Session = Depends(get_db)):
    fe = settings.FRONTEND_URL
    if error or not code:
        return RedirectResponse(f"{fe}/login?error=oauth_denied")
    try:
        if decode_token(state, "oauth_state").get("p") != provider: raise jwt.InvalidTokenError()
    except jwt.PyJWTError:
        return RedirectResponse(f"{fe}/login?error=oauth_state")
    try:
        prof = fetch_profile(provider, code)
    except Exception:
        return RedirectResponse(f"{fe}/login?error=oauth_failed")
    if not prof.get("email"):
        return RedirectResponse(f"{fe}/login?error=oauth_no_email")
    email = prof["email"].lower()
    user = db.scalar(select(User).where(User.oauth_provider == provider, User.oauth_sub == prof["sub"]))
    if not user:
        user = db.scalar(select(User).where(func.lower(User.email) == email))
        if user:  # link to existing account (provider email is verified)
            user.oauth_provider, user.oauth_sub = provider, prof["sub"]
        else:
            base = "".join(ch for ch in email.split("@")[0] if ch.isalnum() or ch in "._-")[:24] or "user"
            uname, i = base, 1
            while db.scalar(select(User).where(func.lower(User.username) == uname.lower())):
                i += 1; uname = f"{base}{i}"
            first = (db.scalar(select(func.count()).select_from(User)) or 0) == 0
            user = User(email=email, username=uname, full_name=prof.get("name", ""), password_hash=None, email_verified=True,
                        role="admin" if first else "user", oauth_provider=provider, oauth_sub=prof["sub"],
                        quota_bytes=settings.DEFAULT_QUOTA_MB * 1024 * 1024)
            db.add(user)
        db.commit()
    if not user.is_active:
        return RedirectResponse(f"{fe}/login?error=disabled")
    if user.mfa_enabled:
        t = create_typed_token("mfa", {"sub": user.id}, settings.MFA_TOKEN_MINUTES)
        return RedirectResponse(f"{fe}/oauth/callback#mfa_token={t}")
    tok = issue_tokens(db, user, request, "oauth")
    audit.log(db, "auth.oauth.login", user.id, "user", user.id, client_ip(request), provider=provider)
    return RedirectResponse(f"{fe}/oauth/callback#access_token={tok['access_token']}&refresh_token={tok['refresh_token']}")
