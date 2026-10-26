import glob, os, re, time
import pyotp, pytest
from datetime import timedelta
from sqlalchemy import select

from app import crypto, mailer
from app.config import settings
from app.database import utcnow
from app.models import ShareLink, SecurityEvent, FileVersion
from tests.conftest import PW, make_user, login, upload


def raw_blobs():
    return [open(p, "rb").read() for p in glob.glob(settings.LOCAL_STORAGE_DIR + "/**/*.enc", recursive=True)]


# ---------------- authentication ----------------
def test_register_login_rbac_and_validation(client):
    a = make_user(client, "alice")                       # first user => admin
    b = make_user(client, "bob")
    assert client.get("/api/auth/me", headers=a["h"]).json()["role"] == "admin"
    assert client.get("/api/auth/me", headers=b["h"]).json()["role"] == "user"
    assert client.post("/api/auth/register", json={"email": "x@example.com", "username": "xx", "password": "weak"}).status_code == 422
    assert client.post("/api/auth/register", json={"email": "alice@example.com", "username": "al2", "password": PW}).status_code == 409
    assert client.get("/api/auth/me").status_code == 401
    assert client.get("/api/admin/overview", headers=b["h"]).status_code == 403
    assert client.get("/api/admin/overview", headers=a["h"]).status_code == 200


def test_lockout_and_bruteforce_detection(client, db):
    make_user(client, "alice"); 
    for i in range(5):
        r = client.post("/api/auth/login", json={"email": "alice@example.com", "password": "Wrong123"}, headers={"X-Forwarded-For": "6.6.6.6"})
        assert r.status_code == 401
    r = client.post("/api/auth/login", json={"email": "alice@example.com", "password": PW})
    assert r.status_code == 423                                         # locked even with right password
    types = {e.type for e in db.scalars(select(SecurityEvent))}
    assert {"brute_force_ip", "account_locked"} <= types


def test_mfa_totp_and_backup_codes(client):
    u = make_user(client, "alice")
    s = client.post("/api/auth/mfa/setup", headers=u["h"]).json()
    assert s["qr_png_base64"] and "otpauth://" in s["otpauth_uri"]
    assert client.post("/api/auth/mfa/enable", json={"code": "000000"}, headers=u["h"]).status_code == 400
    en = client.post("/api/auth/mfa/enable", json={"code": pyotp.TOTP(s["secret"]).now()}, headers=u["h"]).json()
    assert len(en["backup_codes"]) == 8
    r = client.post("/api/auth/login", json={"email": u["email"], "password": PW}).json()
    assert r["mfa_required"] and "access_token" not in r
    bad = client.post("/api/auth/mfa/verify", json={"mfa_token": r["mfa_token"], "code": "123456"})
    assert bad.status_code == 401
    ok = client.post("/api/auth/mfa/verify", json={"mfa_token": r["mfa_token"], "code": pyotp.TOTP(s["secret"]).now()})
    assert ok.status_code == 200 and ok.json()["access_token"]
    # backup code works once
    code = en["backup_codes"][0]
    r2 = client.post("/api/auth/login", json={"email": u["email"], "password": PW}).json()
    assert client.post("/api/auth/mfa/verify", json={"mfa_token": r2["mfa_token"], "code": code}).status_code == 200
    r3 = client.post("/api/auth/login", json={"email": u["email"], "password": PW}).json()
    assert client.post("/api/auth/mfa/verify", json={"mfa_token": r3["mfa_token"], "code": code}).status_code == 401
    # disable
    h = {"Authorization": f"Bearer {ok.json()['access_token']}"}
    assert client.post("/api/auth/mfa/disable", json={"password": PW, "code": pyotp.TOTP(s["secret"]).now()}, headers=h).json()["enabled"] is False


def test_password_recovery(client):
    make_user(client, "alice")
    assert client.post("/api/auth/forgot-password", json={"email": "ghost@example.com"}).status_code == 200  # no enumeration
    assert not mailer.SENT
    assert client.post("/api/auth/forgot-password", json={"email": "alice@example.com"}).status_code == 200
    token = re.search(r"token=([\w-]+)", mailer.SENT[-1]["body"]).group(1)
    assert client.post("/api/auth/reset-password", json={"token": token, "new_password": "weak"}).status_code == 422
    assert client.post("/api/auth/reset-password", json={"token": token, "new_password": "NewPassw0rd"}).status_code == 200
    assert client.post("/api/auth/reset-password", json={"token": token, "new_password": "Another1Pass"}).status_code == 400  # single use
    assert client.post("/api/auth/login", json={"email": "alice@example.com", "password": PW}).status_code == 401
    assert client.post("/api/auth/login", json={"email": "alice@example.com", "password": "NewPassw0rd"}).status_code == 200


def test_sessions_refresh_rotation_logout(client):
    u = make_user(client, "alice")
    rt = u["tok"]["refresh_token"]
    r = client.post("/api/auth/refresh", json={"refresh_token": rt}); assert r.status_code == 200
    new = r.json()
    # reuse of the old (rotated) refresh token => theft detection, everything revoked
    assert client.post("/api/auth/refresh", json={"refresh_token": rt}).status_code == 401
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {new['access_token']}"}).status_code == 401
    u = login(client, "alice@example.com")
    assert client.post("/api/auth/logout", headers=u["h"]).status_code == 200
    assert client.get("/api/auth/me", headers=u["h"]).status_code == 401
    u = login(client, "alice@example.com")
    assert len(client.get("/api/auth/sessions", headers=u["h"]).json()) >= 1
    assert client.post("/api/auth/logout-all", headers=u["h"]).status_code == 200
    assert client.get("/api/auth/me", headers=u["h"]).status_code == 401


def test_swagger_oauth2_password_flow(client):
    make_user(client, "alice")
    r = client.post("/api/auth/token", data={"username": "alice@example.com", "password": PW})
    assert r.status_code == 200
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {r.json()['access_token']}"}).status_code == 200


def test_oauth2_social_login(client, monkeypatch):
    from app.routers import oauth
    assert client.get("/api/auth/oauth/google/login").status_code == 501      # not configured
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "cid"); monkeypatch.setattr(settings, "GOOGLE_CLIENT_SECRET", "sec")
    r = client.get("/api/auth/oauth/google/login", follow_redirects=False)
    assert r.status_code in (302, 307) and "accounts.google.com" in r.headers["location"]
    state = re.search(r"state=([^&]+)", r.headers["location"]).group(1)
    monkeypatch.setattr(oauth, "fetch_profile", lambda name, code: {"sub": "g-123", "email": "Oscar@Example.com", "name": "Oscar"})
    cb = client.get(f"/api/auth/oauth/google/callback?code=abc&state={state}", follow_redirects=False)
    assert cb.status_code in (302, 307)
    loc = cb.headers["location"]; assert loc.startswith("http://fe.test/oauth/callback#access_token=")
    at = re.search(r"access_token=([^&]+)", loc).group(1)
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {at}"}).json()
    assert me["email"] == "oscar@example.com" and me["oauth_provider"] == "google"
    bad = client.get("/api/auth/oauth/google/callback?code=abc&state=forged", follow_redirects=False)
    assert "error=oauth_state" in bad.headers["location"]


# ---------------- files & encryption ----------------
def test_encrypted_storage_roundtrip_and_validation(client):
    u = make_user(client, "alice")
    secret = b"TOP-SECRET-PLAINTEXT-MARKER-98765" * 50
    f = upload(client, u, "plan.txt", secret, description="Q3 plan", tags="finance,q3")
    assert f["category"] == "documents" and f["size"] == len(secret)
    blobs = raw_blobs(); assert blobs and all(b"TOP-SECRET-PLAINTEXT-MARKER" not in b for b in blobs)   # ciphertext at rest
    d = client.get(f"/api/files/{f['id']}/download", headers=u["h"])
    assert d.status_code == 200 and d.content == secret and "attachment" in d.headers["content-disposition"]
    # validation
    assert client.post("/api/files", files={"file": ("evil.exe", b"MZ\x90", "application/octet-stream")}, headers=u["h"]).status_code == 415
    assert client.post("/api/files", files={"file": ("sneaky.txt", b"MZ\x90\x00payload", "text/plain")}, headers=u["h"]).status_code == 415
    assert client.post("/api/files", files={"file": ("empty.txt", b"", "text/plain")}, headers=u["h"]).status_code == 400
    old = settings.MAX_UPLOAD_MB; settings.MAX_UPLOAD_MB = 0
    try: assert client.post("/api/files", files={"file": ("big.txt", b"x" * 10, "text/plain")}, headers=u["h"]).status_code == 413
    finally: settings.MAX_UPLOAD_MB = old
    assert client.post("/api/files", files={"file": ("a.txt", b"x")}).status_code == 401


def test_tamper_detection(client):
    u = make_user(client, "alice"); f = upload(client, u)
    p = glob.glob(settings.LOCAL_STORAGE_DIR + "/**/*.enc", recursive=True)[0]
    data = bytearray(open(p, "rb").read()); data[20] ^= 0xFF; open(p, "wb").write(bytes(data))
    assert client.get(f"/api/files/{f['id']}/download", headers=u["h"]).status_code == 500


def test_folders_search_filter_versions_metadata(client):
    u = make_user(client, "alice")
    fo = client.post("/api/folders", json={"name": "Projects"}, headers=u["h"]).json()
    sub = client.post("/api/folders", json={"name": "2026", "parent_id": fo["id"]}, headers=u["h"]).json()
    assert client.post("/api/folders", json={"name": "Projects"}, headers=u["h"]).status_code == 409
    a = upload(client, u, "budget.csv", b"a,b\n1,2", folder_id=sub["id"])
    b = upload(client, u, "photo.png", b"\x89PNG\r\n\x1a\nxxxx")
    assert b["category"] == "images"
    L = lambda **p: client.get("/api/files", params=p, headers=u["h"]).json()
    assert L(q="budget")["total"] == 1 and L(category="images")["total"] == 1 and L(folder_id=sub["id"])["total"] == 1
    assert L(folder_id="root")["total"] == 1 and L(sort="name", order="asc")["items"][0]["name"] == "budget.csv"
    p = client.patch(f"/api/files/{a['id']}", json={"name": "budget-final.csv", "tags": ["x"], "move_to_root": True}, headers=u["h"]).json()
    assert p["name"] == "budget-final.csv" and p["folder_id"] is None
    # versions
    v2 = client.post(f"/api/files/{a['id']}/versions", files={"file": ("budget.csv", b"a,b\n3,4", "text/csv")}, headers=u["h"])
    assert v2.status_code == 201 and v2.json()["version"] == 2
    assert client.get(f"/api/files/{a['id']}/download", headers=u["h"]).content == b"a,b\n3,4"
    assert client.get(f"/api/files/{a['id']}/download?version=1", headers=u["h"]).content == b"a,b\n1,2"
    assert len(client.get(f"/api/files/{a['id']}/versions", headers=u["h"]).json()) == 2
    assert client.post(f"/api/files/{a['id']}/versions/1/restore", headers=u["h"]).json()["version"] == 3
    assert client.get(f"/api/files/{a['id']}/download", headers=u["h"]).content == b"a,b\n1,2"
    # folder delete rules
    assert client.delete(f"/api/folders/{fo['id']}", headers=u["h"]).status_code == 409
    assert client.delete(f"/api/folders/{fo['id']}?force=true", headers=u["h"]).status_code == 200
    # delete file removes blobs
    n = len(raw_blobs()); assert client.delete(f"/api/files/{a['id']}", headers=u["h"]).status_code == 200
    assert len(raw_blobs()) < n and client.get(f"/api/files/{a['id']}", headers=u["h"]).status_code == 404


def test_quota_and_isolation(client, db):
    from app.models import User
    a = make_user(client, "alice"); b = make_user(client, "bob")
    f = upload(client, a)
    assert client.get(f"/api/files/{f['id']}", headers=b["h"]).status_code == 404            # existence not leaked
    assert client.get(f"/api/files/{f['id']}/download", headers=b["h"]).status_code == 404
    assert client.delete(f"/api/files/{f['id']}", headers=b["h"]).status_code == 404
    assert client.get("/api/files", headers=b["h"]).json()["total"] == 0
    u = db.get(User, b["id"]); u.quota_bytes = 10; db.commit()
    assert client.post("/api/files", files={"file": ("q.txt", b"x" * 100, "text/plain")}, headers=b["h"]).status_code == 413


def test_viewer_role_is_read_only(client, db):
    from app.models import User
    a = make_user(client, "alice"); v = make_user(client, "vera")
    db.get(User, v["id"]).role = "viewer"; db.commit()
    assert client.post("/api/files", files={"file": ("a.txt", b"x", "text/plain")}, headers=v["h"]).status_code == 403


# ---------------- sharing ----------------
def test_share_link_limits_expiry_revoke_password(client, db):
    u = make_user(client, "alice"); f = upload(client, u, content=b"shared payload")
    # download limit
    l = client.post(f"/api/files/{f['id']}/links", json={"max_downloads": 2, "expires_in_hours": 1}, headers=u["h"]).json()
    assert l["token"] and l["url"].startswith("http://fe.test/s/")
    meta = client.get(f"/api/public/links/{l['token']}").json()
    assert meta["remaining_downloads"] == 2 and meta["file_name"] == "report.txt"
    for _ in range(2):
        r = client.get(f"/api/public/links/{l['token']}/download"); assert r.status_code == 200 and r.content == b"shared payload"
    assert client.get(f"/api/public/links/{l['token']}/download").status_code == 410
    assert client.get(f"/api/files/{f['id']}/links", headers=u["h"]).json()[0]["status"] == "exhausted"
    # token is stored hashed only
    assert db.scalars(select(ShareLink)).first().token_hash != l["token"]
    # expiry
    l2 = client.post(f"/api/files/{f['id']}/links", json={"expires_in_hours": 1}, headers=u["h"]).json()
    row = db.get(ShareLink, l2["id"]); row.expires_at = utcnow() - timedelta(minutes=1); db.commit()
    assert client.get(f"/api/public/links/{l2['token']}/download").status_code == 410
    # revoke
    l3 = client.post(f"/api/files/{f['id']}/links", json={}, headers=u["h"]).json()
    assert client.get(f"/api/public/links/{l3['token']}/download").status_code == 200
    assert client.delete(f"/api/links/{l3['id']}", headers=u["h"]).status_code == 200
    assert client.get(f"/api/public/links/{l3['token']}/download").status_code == 410
    # unknown token
    assert client.get("/api/public/links/nope/download").status_code == 404
    # password protected
    l4 = client.post(f"/api/files/{f['id']}/links", json={"password": "open-sesame"}, headers=u["h"]).json()
    assert client.get(f"/api/public/links/{l4['token']}").json()["requires_password"] is True
    assert client.get(f"/api/public/links/{l4['token']}/download").status_code == 401
    assert client.get(f"/api/public/links/{l4['token']}/download", headers={"X-Share-Password": "wrong"}).status_code == 401
    assert client.get(f"/api/public/links/{l4['token']}/download", headers={"X-Share-Password": "open-sesame"}).status_code == 200


def test_view_only_and_email_restricted_links(client):
    a = make_user(client, "alice"); b = make_user(client, "bob"); c = make_user(client, "carol")
    f = upload(client, a, "pic.png", b"\x89PNG\r\n\x1a\n123")
    v = client.post(f"/api/files/{f['id']}/links", json={"permission": "view"}, headers=a["h"]).json()
    assert client.get(f"/api/public/links/{v['token']}/download").status_code == 403
    pr = client.get(f"/api/public/links/{v['token']}/preview")
    assert pr.status_code == 200 and "inline" in pr.headers["content-disposition"]
    e = client.post(f"/api/files/{f['id']}/links", json={"allowed_email": "bob@example.com"}, headers=a["h"]).json()
    assert client.get(f"/api/public/links/{e['token']}/download").status_code == 403           # anonymous
    assert client.get(f"/api/public/links/{e['token']}/download", headers=c["h"]).status_code == 403   # wrong user
    assert client.get(f"/api/public/links/{e['token']}/download", headers=b["h"]).status_code == 200


def test_direct_user_shares_permissions(client):
    a = make_user(client, "alice"); b = make_user(client, "bob")
    f = upload(client, a, content=b"for bob")
    assert client.post(f"/api/files/{f['id']}/shares", json={"email": "nobody@example.com"}, headers=a["h"]).status_code == 404
    s = client.post(f"/api/files/{f['id']}/shares", json={"email": "bob@example.com", "permission": "view"}, headers=a["h"]).json()
    assert client.get("/api/files?scope=shared", headers=b["h"]).json()["total"] == 1
    assert client.get(f"/api/files/{f['id']}/download", headers=b["h"]).status_code == 403          # view-only
    assert client.get(f"/api/files/{f['id']}/download?inline=true", headers=b["h"]).status_code == 200
    client.post(f"/api/files/{f['id']}/shares", json={"email": "bob@example.com", "permission": "download"}, headers=a["h"])
    assert client.get(f"/api/files/{f['id']}/download", headers=b["h"]).content == b"for bob"
    assert client.post(f"/api/files/{f['id']}/versions", files={"file": ("r.txt", b"v2", "text/plain")}, headers=b["h"]).status_code == 403
    assert client.patch(f"/api/files/{f['id']}", json={"name": "hack.txt"}, headers=b["h"]).status_code == 403
    assert client.post(f"/api/files/{f['id']}/links", json={}, headers=b["h"]).status_code == 403   # only owner shares
    client.post(f"/api/files/{f['id']}/shares", json={"email": "bob@example.com", "permission": "edit"}, headers=a["h"])
    assert client.post(f"/api/files/{f['id']}/versions", files={"file": ("r.txt", b"v2", "text/plain")}, headers=b["h"]).status_code == 201
    assert client.delete(f"/api/shares/{s['id']}", headers=a["h"]).status_code == 200
    assert client.get(f"/api/files/{f['id']}", headers=b["h"]).status_code == 404


# ---------------- monitoring / notifications / analytics ----------------
def test_audit_tracking_notifications_analytics(client):
    a = make_user(client, "alice"); b = make_user(client, "bob")
    f = upload(client, a)
    l = client.post(f"/api/files/{f['id']}/links", json={}, headers=a["h"]).json()
    client.get(f"/api/public/links/{l['token']}/download", headers={"X-Forwarded-For": "9.9.9.9"})
    client.post(f"/api/files/{f['id']}/shares", json={"email": "bob@example.com"}, headers=a["h"])
    audit = client.get("/api/monitor/audit?action=file.", headers=a["h"]).json()
    acts = {i["action"] for i in audit["items"]}; assert {"file.upload", "file.download"} <= acts
    dls = client.get("/api/monitor/downloads", headers=a["h"]).json()
    assert dls[0]["via_link"] is True and dls[0]["ip"] == "9.9.9.9"
    assert client.get(f"/api/monitor/files/{f['id']}/access", headers=a["h"]).json()
    n = client.get("/api/notifications", headers=a["h"]).json()
    assert n["unread"] >= 1 and any(i["type"] == "download" for i in n["items"])
    nb = client.get("/api/notifications", headers=b["h"]).json()
    assert any(i["type"] == "share" for i in nb["items"])
    assert client.post("/api/notifications/read-all", headers=a["h"]).status_code == 200
    assert client.get("/api/notifications", headers=a["h"]).json()["unread"] == 0
    assert any("bob@example.com" == m["to"] for m in mailer.SENT)                       # email notification sent
    fa = client.get("/api/analytics/files", headers=a["h"]).json()
    assert fa["storage"]["files"] == 1 and fa["sharing"]["links_active"] == 1 and fa["sharing"]["total_link_downloads"] == 1
    assert fa["top_downloaded"][0]["downloads"] == 1 and sum(d["downloads"] for d in fa["downloads_per_day"]) == 1
    sd = client.get("/api/analytics/security", headers=a["h"]).json()
    assert sd["logins"]["success"] >= 1
    assert client.get("/api/monitor/audit?scope=all", headers=b["h"]).status_code == 403
    assert client.get("/api/monitor/audit?scope=all", headers=a["h"]).status_code == 200


def test_suspicious_activity_detection(client, db):
    a = make_user(client, "alice"); f = upload(client, a)
    for i in range(10): client.get(f"/api/public/links/bogus{i}/download", headers={"X-Forwarded-For": "7.7.7.7"})
    for i in range(25): client.get(f"/api/files/{f['id']}/download", headers=a["h"])
    types = {e.type for e in db.scalars(select(SecurityEvent))}
    assert {"link_probing", "download_spike"} <= types
    ev = client.get("/api/monitor/security-events", headers=a["h"]).json()
    assert any(e["type"] == "download_spike" for e in ev)
    assert any(n["type"] == "security" for n in client.get("/api/notifications", headers=a["h"]).json()["items"])
    assert client.post(f"/api/monitor/security-events/{ev[0]['id']}/resolve", headers=a["h"]).status_code == 200


def test_expiry_reminders(client, db):
    a = make_user(client, "alice"); f = upload(client, a)
    client.post(f"/api/files/{f['id']}/links", json={"expires_in_hours": 2}, headers=a["h"])
    client.post(f"/api/files/{f['id']}/links", json={"expires_in_hours": 500}, headers=a["h"])
    assert client.post("/api/admin/reminders/run", headers=a["h"]).json()["sent"] == 1
    assert client.post("/api/admin/reminders/run", headers=a["h"]).json()["sent"] == 0
    assert any(n["type"] == "expiry" for n in client.get("/api/notifications", headers=a["h"]).json()["items"])


# ---------------- admin / key management ----------------
def test_key_rotation_rewrap_and_reencrypt(client, db):
    a = make_user(client, "alice"); f = upload(client, a, content=b"rotate me")
    ks = client.get("/api/admin/keys", headers=a["h"]).json(); assert ks["active_version"] == 1
    r = client.post("/api/admin/keys/rotate", json={}, headers=a["h"]).json()
    assert r["new_version"] == 2 and r["rewrapped"] == 1 and r["add_to_MASTER_KEYS"].startswith("2:")
    assert db.scalars(select(FileVersion)).first().key_version in (1, 2)
    db.expire_all(); assert db.scalars(select(FileVersion)).first().key_version == 2
    assert client.get(f"/api/files/{f['id']}/download", headers=a["h"]).content == b"rotate me"
    old = raw_blobs()[0]
    r = client.post("/api/admin/keys/rotate", json={"reencrypt": True}, headers=a["h"]).json()
    assert r["reencrypted"] == 1 and raw_blobs()[0] != old                               # fresh DEK + nonce => new ciphertext
    assert client.get(f"/api/files/{f['id']}/download", headers=a["h"]).content == b"rotate me"


def test_admin_user_management_and_system(client):
    a = make_user(client, "alice"); b = make_user(client, "bob")
    assert client.patch(f"/api/admin/users/{a['id']}", json={"is_active": False}, headers=a["h"]).status_code == 400
    assert client.patch(f"/api/admin/users/{b['id']}", json={"role": "viewer", "quota_mb": 5}, headers=a["h"]).status_code == 200
    assert client.get("/api/auth/me", headers=b["h"]).json()["role"] == "viewer"
    assert client.patch(f"/api/admin/users/{b['id']}", json={"is_active": False}, headers=a["h"]).status_code == 200
    assert client.get("/api/auth/me", headers=b["h"]).status_code == 401
    sysi = client.get("/api/admin/system", headers=a["h"]).json()
    assert sysi["database"]["ok"] and sysi["storage"]["ok"] and sysi["cache"]["backend"] == "memory"
    upload(client, a)
    m = client.get("/api/admin/metrics", headers=a["h"]).json()
    assert "encrypt" in m["timings"] and "api_latency" in m["timings"]
    ov = client.get("/api/admin/overview", headers=a["h"]).json(); assert ov["users"]["total"] == 2 and ov["storage"]["files"] == 1


def test_security_headers_and_health(client):
    r = client.get("/api/health"); assert r.json()["status"] == "ok"
    assert r.headers["x-frame-options"] == "DENY" and "strict-transport-security" in r.headers


def test_crypto_primitives():
    blob, wrapped, kv, sha = crypto.encrypt_bytes(b"abc", b"aad")
    assert crypto.decrypt_bytes(blob, wrapped, kv, b"aad") == b"abc"
    with pytest.raises(Exception): crypto.decrypt_bytes(blob, wrapped, kv, b"other-aad")
    b2, w2, *_ = crypto.encrypt_bytes(b"abc", b"aad"); assert b2 != blob and w2 != wrapped   # unique key + nonce per file
