# Milestone checklist (spec §5–6)

## M1 (Weeks 1–2) Init, design, core
- Architecture & schema: `backend/app/models.py`, `backend/alembic/versions/0001_initial_schema.py`, `docs/ARCHITECTURE.md`
- React/Next.js + FastAPI setup, PostgreSQL/MongoDB/Redis: `docker-compose.yml`, `frontend/`, `backend/`
- Auth + RBAC (admin/user/viewer): `routers/auth.py`, `deps.py`
- Secure upload, file dashboard: `routers/files.py`, `frontend/src/components/tabs/FilesTab.tsx`
- Tests: `test_register_login_rbac_and_validation`, `test_encrypted_storage_roundtrip_and_validation`, `test_folders_search_filter_versions_metadata`

## M2 (Weeks 3–4) Encryption & sharing
- AES-256-GCM, per-file keys, key mgmt/rotation, decrypt-in-memory: `crypto.py`, `services.py`, `routers/admin.py`
- Cloud storage (S3/Azure/local): `storage.py`
- Share links (expiry, limits, password, email lock, revoke), user shares & access levels: `routers/shares.py`, `public.py`
- Tests: `test_share_link_limits_expiry_revoke_password`, `test_view_only_and_email_restricted_links`, `test_direct_user_shares_permissions`, `test_key_rotation_rewrap_and_reencrypt`, `test_tamper_detection`

## M3 (Weeks 5–6) Monitoring, notifications, analytics
- Audit log (MongoDB / SQL fallback), activity tracking, suspicious activity: `audit.py`, `monitor.py`, `routers/monitoring.py`
- Notifications + email + expiry reminders: `notifications.py`, `mailer.py`, `reminders.py`
- Dashboards: `routers/analytics.py`, `routers/admin.py`, frontend Analytics/Security/Admin tabs
- Tests: `test_audit_tracking_notifications_analytics`, `test_suspicious_activity_detection`, `test_expiry_reminders`, `test_lockout_and_bruteforce_detection`

## M4 (Weeks 7–8) Testing, deployment, documentation
- Security testing: 22 pytest end-to-end tests (also green on PostgreSQL), tamper/lockout/rate-limit/RBAC cases
- Performance metrics: `scripts/benchmark.py`, Admin → System → metrics, `/api/admin/metrics`
- Docker: both `Dockerfile`s + `docker-compose.yml`; cloud notes in README
- Documentation: `README.md`, `docs/ARCHITECTURE.md`, this file, interactive API docs at `/docs`
