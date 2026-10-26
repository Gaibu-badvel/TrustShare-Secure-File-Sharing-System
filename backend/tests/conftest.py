import base64, os, tempfile
_tmp = tempfile.mkdtemp(prefix="ts_test_")
os.environ.update({
    "DATABASE_URL": os.environ.get("TEST_DATABASE_URL", f"sqlite:///{_tmp}/t.db"), "LOCAL_STORAGE_DIR": f"{_tmp}/enc", "OUTBOX_DIR": f"{_tmp}/outbox",
    "MASTER_KEYS": "1:" + base64.b64encode(os.urandom(32)).decode(), "RUN_BACKGROUND_JOBS": "false",
    "AUTH_RATE_LIMIT_PER_MINUTE": "10000", "ENV": "test", "MONGO_URL": "", "REDIS_URL": "", "FRONTEND_URL": "http://fe.test",
    "BACKEND_URL": "http://be.test",
})
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import Base, engine, SessionLocal
from app import cache, mailer

PW = "Str0ngPass!"


@pytest.fixture()
def client():
    Base.metadata.drop_all(engine)
    import shutil; shutil.rmtree(os.environ['LOCAL_STORAGE_DIR'], ignore_errors=True)
    from app.storage import get_storage; get_storage().__init__(os.environ['LOCAL_STORAGE_DIR'])
    with TestClient(app) as c:
        cache._mem.clear(); mailer.SENT.clear()
        yield c


@pytest.fixture()
def db():
    with SessionLocal() as s: yield s


def make_user(client, name, email=None, password=PW, ip="10.0.0.1"):
    email = email or f"{name}@example.com"
    r = client.post("/api/auth/register", json={"email": email, "username": name, "password": password, "full_name": name.title()})
    assert r.status_code == 201, r.text
    return login(client, email, password, ip)


def login(client, email, password=PW, ip="10.0.0.1"):
    r = client.post("/api/auth/login", json={"email": email, "password": password}, headers={"X-Forwarded-For": ip})
    assert r.status_code == 200, r.text
    d = r.json()
    return {"h": {"Authorization": f"Bearer {d['access_token']}"}, "tok": d, "id": d["user"]["id"], "email": email}


def upload(client, u, name="report.txt", content=b"top secret contents 12345", **form):
    r = client.post("/api/files", files={"file": (name, content, "text/plain")}, data=form, headers=u["h"])
    assert r.status_code == 201, r.text
    return r.json()
