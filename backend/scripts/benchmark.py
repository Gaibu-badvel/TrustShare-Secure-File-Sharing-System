"""Performance metrics: encryption/decryption throughput.   python scripts/benchmark.py"""
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from app import crypto
for mb in (1, 10, 50):
    data = os.urandom(mb * 1024 * 1024)
    t = time.perf_counter(); blob, w, kv, _ = crypto.encrypt_bytes(data); te = time.perf_counter() - t
    t = time.perf_counter(); crypto.decrypt_bytes(blob, w, kv); td = time.perf_counter() - t
    print(f"{mb:>3} MB  encrypt {te*1000:7.1f} ms ({mb/te:6.0f} MB/s)   decrypt {td*1000:7.1f} ms ({mb/td:6.0f} MB/s)")
