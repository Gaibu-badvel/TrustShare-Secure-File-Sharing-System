from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, desc, func, update
from sqlalchemy.orm import Session
from ..database import get_db
from ..deps import get_current_user
from ..models import Notification, User

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


@router.get("")
def list_notifications(unread_only: bool = False, limit: int = 50, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    q = select(Notification).where(Notification.user_id == user.id)
    if unread_only: q = q.where(Notification.is_read == False)  # noqa: E712
    rows = db.scalars(q.order_by(desc(Notification.created_at)).limit(min(limit, 200))).all()
    unread = db.scalar(select(func.count()).select_from(Notification).where(Notification.user_id == user.id, Notification.is_read == False)) or 0  # noqa: E712
    return {"unread": unread, "items": [{"id": n.id, "type": n.type, "title": n.title, "message": n.message, "link": n.link,
                                         "is_read": n.is_read, "created_at": n.created_at} for n in rows]}


@router.post("/read-all")
def read_all(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db.execute(update(Notification).where(Notification.user_id == user.id).values(is_read=True)); db.commit(); return {"ok": True}


@router.post("/{nid}/read")
def read_one(nid: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    n = db.get(Notification, nid)
    if not n or n.user_id != user.id: raise HTTPException(404, "Not found")
    n.is_read = True; db.commit(); return {"ok": True}


@router.delete("/{nid}")
def delete_one(nid: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    n = db.get(Notification, nid)
    if not n or n.user_id != user.id: raise HTTPException(404, "Not found")
    db.delete(n); db.commit(); return {"ok": True}
