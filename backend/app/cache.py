"""Redis-backed cache/rate-limit/token-blacklist with automatic in-memory fallback."""
import threading, time
from .config import settings

_redis = None
_tried = False
_mem: dict[str, tuple[float, int | str]] = {}
_lock = threading.Lock()


def redis_client():
    global _redis, _tried
    if _tried:
        return _redis
    _tried = True
    if settings.REDIS_URL:
        try:
            import redis
            c = redis.Redis.from_url(settings.REDIS_URL, socket_connect_timeout=1, decode_responses=True)
            c.ping(); _redis = c
        except Exception:
            _redis = None
    return _redis


def backend() -> str:
    return "redis" if redis_client() else "memory"


def incr(key: str, ttl: int) -> int:
    r = redis_client()
    if r:
        p = r.pipeline(); p.incr(key); p.expire(key, ttl, nx=True); return int(p.execute()[0])
    now = time.time()
    with _lock:
        exp, val = _mem.get(key, (0, 0))
        if exp < now: exp, val = now + ttl, 0
        val += 1; _mem[key] = (exp, val); return val


def set_(key: str, value: str, ttl: int):
    r = redis_client()
    if r: r.setex(key, ttl, value); return
    with _lock: _mem[key] = (time.time() + ttl, value)


def get(key: str):
    r = redis_client()
    if r: return r.get(key)
    with _lock:
        exp, val = _mem.get(key, (0, None))
        if exp < time.time(): _mem.pop(key, None); return None
        return val


def delete(key: str):
    r = redis_client()
    if r: r.delete(key); return
    with _lock: _mem.pop(key, None)


def blacklist_token(jti: str, ttl: int): set_(f"bl:{jti}", "1", ttl)
def is_blacklisted(jti: str) -> bool: return get(f"bl:{jti}") is not None
