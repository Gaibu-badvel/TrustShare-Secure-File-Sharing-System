"""Expiration reminders (run periodically in the background or on demand by an admin)."""
from datetime import timedelta
from sqlalchemy import select
from sqlalchemy.orm import Session
from .config import settings
from .database import utcnow
from .models import File, ShareLink
from .notifications import notify


def send_expiry_reminders(db: Session) -> int:
    now = utcnow(); horizon = now + timedelta(hours=settings.REMINDER_HOURS)
    rows = db.scalars(select(ShareLink).where(ShareLink.revoked == False, ShareLink.reminder_sent == False,  # noqa: E712
                                              ShareLink.expires_at.is_not(None), ShareLink.expires_at > now, ShareLink.expires_at <= horizon)).all()
    for l in rows:
        f = db.get(File, l.file_id)
        notify(db, l.created_by, "expiry", f"Share link expiring soon: {f.name if f else 'file'}",
               f"Your link expires at {l.expires_at:%Y-%m-%d %H:%M} UTC. Create a new one if recipients still need access.", "/dashboard?tab=shared")
        l.reminder_sent = True
    db.commit()
    return len(rows)
