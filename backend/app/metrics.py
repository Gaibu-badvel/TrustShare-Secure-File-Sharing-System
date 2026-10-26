"""Tiny in-process performance metrics (encryption speed, API latency, ...)."""
import threading, time
from collections import defaultdict, deque
from contextlib import contextmanager

_lock = threading.Lock()
_samples: dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
_counters: dict[str, int] = defaultdict(int)


def observe(name: str, value: float):
    with _lock: _samples[name].append(value)


def count(name: str, n: int = 1):
    with _lock: _counters[name] += n


@contextmanager
def timer(name: str):
    t = time.perf_counter()
    try: yield
    finally: observe(name, (time.perf_counter() - t) * 1000)


def snapshot() -> dict:
    with _lock:
        out = {}
        for k, v in _samples.items():
            s = sorted(v)
            if s:
                out[k] = {"count": len(s), "avg_ms": round(sum(s) / len(s), 2),
                          "p95_ms": round(s[min(len(s) - 1, int(len(s) * .95))], 2), "max_ms": round(s[-1], 2)}
        return {"timings": out, "counters": dict(_counters)}
