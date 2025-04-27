from ..models import ActivityLog, db
from flask_jwt_extended import get_jwt_identity

def log_action(actor_id, action, target=None):
    log = ActivityLog(
        actor_id=actor_id,
        action=action,
        target=target
    )
    db.session.add(log)
    db.session.commit()