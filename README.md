# 🔐 TrustShare — Secure File-Sharing System

FastAPI + Next.js platform: upload, AES-256-GCM encrypted storage, controlled sharing, temporary links,
download tracking, audit logging, MFA/OAuth2, notifications and analytics dashboards. Implements every module in the project spec.

## Quick start (pick one)

### A. Docker (everything: Postgres, MongoDB, Redis, API, UI)
```bash
docker compose up --build
```
Open http://localhost:3000 — the **first account you register becomes admin**. API docs: http://localhost:8000/docs.

### B. No Docker (SQLite + in-memory fallbacks — zero setup)
```bash
# terminal 1 – backend
cd backend
python3 -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# terminal 2 – frontend
cd frontend
cp .env.example .env.local
npm install && npm run dev
```
### C. Real databases locally, apps outside Docker
`docker compose up -d postgres mongo redis`, then in `backend/.env` set
`DATABASE_URL=postgresql+psycopg2://trustshare:trustshare@localhost:5432/trustshare`, `MONGO_URL=mongodb://localhost:27017`,
`REDIS_URL=redis://localhost:6379/0`, run `alembic upgrade head`, and start the apps as in B.

Without MongoDB/Redis configured the app automatically falls back (audit log → SQL table, rate limits/blacklist → memory).
Emails are written to `backend/data/outbox/` and logged until you set `SMTP_HOST` — **this is where the password-reset link appears in dev**.

## Verify it works
```bash
cd backend && pytest -q                      # 22 end-to-end tests (SQLite; set TEST_DATABASE_URL to test Postgres)
python scripts/benchmark.py                  # encryption/decryption throughput
```

## Module map (spec → code)
| Spec module | Where |
|---|---|
| 1 Authentication: register/login, MFA, recovery, sessions, JWT, OAuth2 | `backend/app/routers/auth.py`, `oauth.py`, `security.py`; UI: `login`, `register`, `forgot/reset-password`, `oauth/callback`, Settings tab |
| 2 File management: upload, categories, folders, search/filter, versions, metadata | `routers/files.py`, `folders.py`, `services.py`; UI: Files tab |
| 3 Secure sharing: links, permissions, expiry, access levels, download restrictions, share activity | `routers/shares.py`, `public.py`; UI: share modal, Sharing tab, `/s/[token]` |
| 4 Encryption & security: AES-256, key mgmt, rotation, RBAC, rate limiting, headers | `crypto.py`, `storage.py`, `deps.py`, `routers/admin.py`, `scripts/rotate_keys.py` |
| 5 Access monitoring: download tracking, history, login activity, audit, security events, suspicious detection | `monitor.py`, `audit.py`, `routers/monitoring.py`; UI: Activity + Security tabs |
| 6 Notifications: share, access, security, email, download, expiration | `notifications.py`, `mailer.py`, `reminders.py`; UI: Notifications tab |
| 7 Analytics: file, security, admin dashboards | `routers/analytics.py`, `admin.py`; UI: Analytics, Security, Admin tabs |
See `docs/MILESTONES.md` for the week-by-week checklist and `docs/ARCHITECTURE.md` for design details.

## Encryption design
Upload → validate (type, size, magic bytes, quota) → generate unique 256-bit data key → AES-256-GCM encrypt in server memory →
only `nonce‖ciphertext‖tag` goes to storage (local / S3 / Azure Blob) → data key wrapped by a versioned master key and stored in PostgreSQL.
Download → authorise → fetch → unwrap key → decrypt **in memory** → verify SHA-256 → stream. Keys are never returned by any endpoint.
Rotation: Admin → Keys (re-wrap all data keys under a new master key, or re-encrypt every file with fresh keys), or `python scripts/rotate_keys.py [--reencrypt]` from cron.

## Going to production
* Set `ENV=production`, a 64+ char `JWT_SECRET`, `MASTER_KEYS` (`python scripts/generate_master_key.py 1`; keep in a secrets manager/KMS), `AUTO_CREATE_TABLES=false`, `alembic upgrade head`.
* Terminate TLS in front (NGINX/ALB). Set `FRONTEND_URL`, `BACKEND_URL`, `CORS_ORIGINS` to real HTTPS origins and build the frontend with `NEXT_PUBLIC_API_URL`.
* S3: `STORAGE_BACKEND=s3`, `S3_BUCKET`, AWS credentials via env/IAM role. Azure: `STORAGE_BACKEND=azure`, `AZURE_CONNECTION_STRING`.
* OAuth2: create Google/GitHub OAuth apps with redirect `https://API/api/auth/oauth/<provider>/callback`; set the client id/secret.
* AWS/Azure deploy: push the two Dockerfiles to ECR/ACR → ECS Fargate / App Service / Container Apps; managed Postgres (RDS), DocumentDB/Cosmos or Atlas for Mongo, ElastiCache for Redis.

## Honest notes
* Access/refresh tokens live in `localStorage` (simple, SPA-friendly); for stricter XSS posture move the refresh token to an httpOnly cookie.
* Files are encrypted/decrypted in memory (spec design), so very large files are bounded by `MAX_UPLOAD_MB` (default 50).
* S3/Azure backends use the official SDKs but were not exercised against live cloud accounts here; local storage, SQLite and PostgreSQL were.
* Google/GitHub OAuth flow is tested with the provider calls mocked; you need your own client credentials for the real thing.
