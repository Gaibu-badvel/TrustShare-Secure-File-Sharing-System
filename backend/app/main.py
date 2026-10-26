import asyncio, logging, time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import crypto, metrics
from .config import settings
from .database import SessionLocal, init_db
from .routers import admin, analytics, auth, files, folders, monitoring, notifications, oauth, public, shares

log = logging.getLogger("trustshare")


async def _background():
    from .reminders import send_expiry_reminders
    while True:
        await asyncio.sleep(settings.REMINDER_INTERVAL_SECONDS)
        try:
            with SessionLocal() as db: send_expiry_reminders(db)
        except Exception as e:  # keep the loop alive
            log.error("reminder job failed: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.AUTO_CREATE_TABLES: init_db()
    crypto.load_keys()
    if settings.is_prod and settings.JWT_SECRET.startswith("change-me"):
        raise RuntimeError("Set a strong JWT_SECRET in production")
    task = asyncio.create_task(_background()) if settings.RUN_BACKGROUND_JOBS else None
    yield
    if task: task.cancel()


app = FastAPI(title="TrustShare API", version="1.0.0", description="Secure file-sharing system", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_list, allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
                   expose_headers=["Content-Disposition", "X-TrustShare-Version"])


@app.middleware("http")
async def security_headers(request: Request, call_next):
    t = time.perf_counter()
    try:
        resp = await call_next(request)
    except Exception:
        log.exception("unhandled error")
        resp = JSONResponse({"detail": "Internal server error"}, status_code=500)
    metrics.observe("api_latency", (time.perf_counter() - t) * 1000)
    resp.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
                         "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
                         "Permissions-Policy": "camera=(), microphone=(), geolocation=()"})
    return resp


for r in (auth.router, oauth.router, files.router, folders.router, shares.router, public.router, monitoring.router,
          notifications.router, analytics.router, admin.router):
    app.include_router(r)


@app.get("/api/health", tags=["system"])
def health():
    return {"status": "ok", "app": settings.APP_NAME}
