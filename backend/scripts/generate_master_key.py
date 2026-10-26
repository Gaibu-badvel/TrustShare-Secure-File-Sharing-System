"""Print a fresh base64 AES-256 master key in MASTER_KEYS format:  python scripts/generate_master_key.py [version]"""
import base64, os, sys
print(f"{sys.argv[1] if len(sys.argv) > 1 else 1}:{base64.b64encode(os.urandom(32)).decode()}")
