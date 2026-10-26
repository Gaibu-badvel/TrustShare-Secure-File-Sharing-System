"""Pluggable object storage for *encrypted* blobs: local disk, AWS S3 / MinIO, Azure Blob."""
from pathlib import Path
from .config import settings


class Storage:
    name = "base"
    def put(self, key: str, data: bytes) -> None: raise NotImplementedError
    def get(self, key: str) -> bytes: raise NotImplementedError
    def delete(self, key: str) -> None: raise NotImplementedError
    def health(self) -> bool: return True


class LocalStorage(Storage):
    name = "local"
    def __init__(self, root: str):
        self.root = Path(root); self.root.mkdir(parents=True, exist_ok=True)
    def _p(self, key: str) -> Path:
        p = (self.root / key).resolve()
        if self.root.resolve() not in p.parents:
            raise ValueError("invalid storage key")
        return p
    def put(self, key, data):
        p = self._p(key); p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp"); tmp.write_bytes(data); tmp.replace(p)
    def get(self, key): return self._p(key).read_bytes()
    def delete(self, key):
        try: self._p(key).unlink()
        except FileNotFoundError: pass
    def health(self): return self.root.exists()


class S3Storage(Storage):
    name = "s3"
    def __init__(self):
        import boto3
        kw = {"region_name": settings.S3_REGION}
        if settings.S3_ENDPOINT_URL: kw["endpoint_url"] = settings.S3_ENDPOINT_URL
        self.c = boto3.client("s3", **kw); self.bucket = settings.S3_BUCKET
    def put(self, key, data): self.c.put_object(Bucket=self.bucket, Key=key, Body=data, ServerSideEncryption="AES256") if not settings.S3_ENDPOINT_URL else self.c.put_object(Bucket=self.bucket, Key=key, Body=data)
    def get(self, key): return self.c.get_object(Bucket=self.bucket, Key=key)["Body"].read()
    def delete(self, key): self.c.delete_object(Bucket=self.bucket, Key=key)
    def health(self):
        try: self.c.head_bucket(Bucket=self.bucket); return True
        except Exception: return False


class AzureStorage(Storage):
    name = "azure"
    def __init__(self):
        from azure.storage.blob import BlobServiceClient
        svc = BlobServiceClient.from_connection_string(settings.AZURE_CONNECTION_STRING)
        self.cc = svc.get_container_client(settings.AZURE_CONTAINER)
        try: self.cc.create_container()
        except Exception: pass
    def put(self, key, data): self.cc.upload_blob(key, data, overwrite=True)
    def get(self, key): return self.cc.download_blob(key).readall()
    def delete(self, key):
        try: self.cc.delete_blob(key)
        except Exception: pass
    def health(self):
        try: self.cc.get_container_properties(); return True
        except Exception: return False


_storage: Storage | None = None

def get_storage() -> Storage:
    global _storage
    if _storage is None:
        b = settings.STORAGE_BACKEND.lower()
        _storage = S3Storage() if b == "s3" else AzureStorage() if b == "azure" else LocalStorage(settings.LOCAL_STORAGE_DIR)
    return _storage
