"""In-app + email notifications."""
from sqlalchemy.orm import Session
from .models import Notification, User
from .mailer import send_email
from .config import settings


def notify(db: Session, user: User | str, type_: str, title: str, message: str = "", link: str = "", email: bool = True):
    if isinstance(user, str):
        user = db.get(User, user)
    if not user:
        return None
    n = Notification(user_id=user.id, type=type_, title=title, message=message, link=link)
    db.add(n); db.commit()
    if email and user.notify_email and user.is_active:
        url = f"{settings.FRONTEND_URL}{link}" if link else settings.FRONTEND_URL
        send_email(user.email, f"[{settings.APP_NAME}] {title}", f"{message}\n\nOpen TrustShare: {url}\n")
    return n
