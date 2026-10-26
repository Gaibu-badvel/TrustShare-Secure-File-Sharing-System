"""
Server-side AES-256-GCM envelope encryption with key rotation.

  * Every file version gets its own random 256-bit data key (DEK).
  * The DEK is wrapped (AES-256-GCM) with a master key (KEK) identified by a version number.
  * Only ciphertext (nonce || ciphertext || tag) is written to cloud storage.
  * Keys never leave the server and are never returned by the API.
  * Rotation = add a new master key version and re-wrap all DEKs (cheap), or fully
    re-encrypt a file with a brand-new DEK (see rotate_file_key in routers/admin.py).
Production: put MASTER_KEYS in a secrets manager / KMS-backed env var.
"""
import base64, hashlib, json, os, threading
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .config import settings, BASE_DIR

NONCE = 12
_lock = threading.Lock()
_keys: dict[int, bytes] = {}
_KEYFILE = BASE_DIR / "data" / "master_keys.json"


def _parse(raw: str) -> dict[int, bytes]:
    out = {}
    for part in filter(None, (p.strip() for p in raw.split(","))):
        ver, b64 = part.split(":", 1)
        key = base64.b64decode(b64)
        if len(key) != 32:
            raise ValueError("master key must be 32 bytes (AES-256)")
        out[int(ver)] = key
    return out


def load_keys() -> dict[int, bytes]:
    global _keys
    with _lock:
        if settings.MASTER_KEYS:
            _keys = _parse(settings.MASTER_KEYS)
        elif _KEYFILE.exists():
            _keys = {int(k): base64.b64decode(v) for k, v in json.loads(_KEYFILE.read_text()).items()}
        else:
            if settings.is_prod:
                raise RuntimeError("MASTER_KEYS must be set in production")
            _KEYFILE.parent.mkdir(parents=True, exist_ok=True)
            _keys = {1: os.urandom(32)}
            _persist()
        return _keys


def _persist():
    if settings.MASTER_KEYS:
        return  # env-managed; operator must store new key themselves
    _KEYFILE.write_text(json.dumps({str(k): base64.b64encode(v).decode() for k, v in _keys.items()}))
    try: os.chmod(_KEYFILE, 0o600)
    except OSError: pass


def keys() -> dict[int, bytes]:
    return _keys or load_keys()


def active_version() -> int:
    ks = keys()
    if settings.ACTIVE_KEY_VERSION and settings.ACTIVE_KEY_VERSION in ks:
        return settings.ACTIVE_KEY_VERSION
    return max(ks)


def add_master_key() -> tuple[int, str | None]:
    """Create a new master key version. Returns (version, base64 if env-managed else None)."""
    with _lock:
        ks = keys()
        ver = max(ks) + 1
        ks[ver] = os.urandom(32)
        _persist()
        return ver, (base64.b64encode(ks[ver]).decode() if settings.MASTER_KEYS else None)


def wrap(dek: bytes, version: int | None = None) -> tuple[str, int]:
    version = version or active_version()
    nonce = os.urandom(NONCE)
    ct = AESGCM(keys()[version]).encrypt(nonce, dek, b"trustshare-dek")
    return base64.b64encode(nonce + ct).decode(), version


def unwrap(wrapped_b64: str, version: int) -> bytes:
    raw = base64.b64decode(wrapped_b64)
    return AESGCM(keys()[version]).decrypt(raw[:NONCE], raw[NONCE:], b"trustshare-dek")


def rewrap(wrapped_b64: str, old_version: int, new_version: int | None = None) -> tuple[str, int]:
    return wrap(unwrap(wrapped_b64, old_version), new_version)


def encrypt_bytes(plaintext: bytes, aad: bytes = b"") -> tuple[bytes, str, int, str]:
    """-> (blob, wrapped_key_b64, key_version, sha256_of_plaintext)"""
    dek = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(NONCE)
    blob = nonce + AESGCM(dek).encrypt(nonce, plaintext, aad or None)
    wrapped, ver = wrap(dek)
    return blob, wrapped, ver, hashlib.sha256(plaintext).hexdigest()


def decrypt_bytes(blob: bytes, wrapped_key: str, key_version: int, aad: bytes = b"") -> bytes:
    dek = unwrap(wrapped_key, key_version)
    return AESGCM(dek).decrypt(blob[:NONCE], blob[NONCE:], aad or None)
