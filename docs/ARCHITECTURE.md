# Architecture
```
Browser (Next.js) ──HTTPS──▶ FastAPI gateway layer (CORS, security headers, rate limit, JWT/RBAC, audit)
                                 │
   ┌────────┬────────┬───────────┼────────────┬─────────────┬────────────┐
 Auth    Files    Encryption   Sharing     Notification   Analytics
(JWT,MFA, (upload, (AES-256-GCM, (links,     (in-app,      (file, security,
 OAuth2)  folders,  key wrap/    user shares, email,        admin dashboards)
          versions) rotation)    limits)     reminders)
   └────────┴────────┴───────────┴────────────┴─────────────┴────────────┘
 PostgreSQL (users, files, versions, wrapped keys, shares, events)   MongoDB (audit log; SQL fallback)
 Redis (rate limits, token blacklist; memory fallback)               Object storage: local | S3 | Azure Blob (ciphertext only)
```
Spec's message queue (RabbitMQ/Kafka) is replaced by in-process FastAPI background tasks + an asyncio reminder loop; notification
calls are isolated in `notifications.py`, so swapping in a queue is a one-file change.

## Security controls
bcrypt (cost 12) · JWT access (15 min) + rotating refresh tokens with reuse detection · TOTP MFA + one-time backup codes · account lockout ·
per-IP rate limits · share tokens stored as SHA-256 hashes (shown once) · atomic download-limit enforcement · bad-password throttling on links ·
upload type allow-list + executable magic-byte block + size/quota limits · GCM auth tags + SHA-256 integrity check on every read ·
nosniff/sandbox CSP on served files · HSTS/X-Frame-Options · no user enumeration on password recovery · existence not leaked on forbidden files.

## Suspicious-activity rules (`monitor.py`)
brute force per IP (5 fails/10 min) · repeated failures per account · account locked · login from new IP · download spike (25/min) ·
share-link probing (10 invalid/blocked attempts/10 min) · share-password guessing · refresh-token reuse · MFA disabled.
Events create SecurityEvent rows, audit entries, in-app notifications (and email to the user; high-severity also alerts admins).
