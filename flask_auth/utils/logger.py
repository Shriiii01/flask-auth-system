from ..models import ActivityLog
from sqlalchemy.orm import Session

def log_action(db: Session, actor_id: int, action: str, target: str = None):
    log = ActivityLog(
        actor_id=actor_id,
        action=action,
        target=target
    )
    db.add(log)
    db.commit()