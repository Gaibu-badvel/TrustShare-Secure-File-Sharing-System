"""Email delivery: SMTP when configured, otherwise a dev outbox (files + log)."""
import logging, smtplib, time
from email.message import EmailMessage
from pathlib import Path
from .config import settings

log = logging.getLogger("trustshare.mail")
SENT: list[dict] = []   # in-process record (used by tests / dev inspection)


def send_email(to: str, subject: str, body: str, html: str | None = None) -> bool:
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = settings.MAIL_FROM, to, subject
    msg.set_content(body)
    if html: msg.add_alternative(html, subtype="html")
    SENT.append({"to": to, "subject": subject, "body": body})
    del SENT[:-200]
    if not settings.SMTP_HOST:
        out = Path(settings.OUTBOX_DIR); out.mkdir(parents=True, exist_ok=True)
        (out / f"{int(time.time()*1000)}-{to.replace('@','_at_')}.eml").write_text(msg.as_string())
        log.info("[DEV OUTBOX] to=%s subject=%s\n%s", to, subject, body)
        return True
    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as s:
            if settings.SMTP_TLS: s.starttls()
            if settings.SMTP_USER: s.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            s.send_message(msg)
        return True
    except Exception as e:  # never break a request because mail failed
        log.error("email send failed: %s", e)
        return False
