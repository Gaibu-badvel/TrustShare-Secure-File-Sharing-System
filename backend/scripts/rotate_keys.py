"""Periodic key rotation from cron/CI:   python scripts/rotate_keys.py [--reencrypt]"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from sqlalchemy import select
from app import crypto, services
from app.database import SessionLocal
from app.models import File, FileVersion
from app.storage import get_storage

reenc = "--reencrypt" in sys.argv
ver, env_b64 = crypto.add_master_key()
n = 0
with SessionLocal() as db:
    for fv in db.scalars(select(FileVersion)).all():
        if reenc:
            f = db.get(File, fv.file_id); data = services.read_version(f, fv)
            blob, w, kv, sha = crypto.encrypt_bytes(data, aad=f"{f.id}:{fv.version}".encode())
            get_storage().put(fv.storage_key, blob); fv.wrapped_key, fv.key_version, fv.sha256 = w, kv, sha
        else:
            fv.wrapped_key, fv.key_version = crypto.rewrap(fv.wrapped_key, fv.key_version, ver)
        n += 1
    db.commit()
print(f"rotated to master key v{ver}; {n} file versions {'re-encrypted' if reenc else 're-wrapped'}")
if env_b64: print(f"ADD THIS TO MASTER_KEYS (comma-separated): {ver}:{env_b64}")
