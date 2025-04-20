from ..models import ActivityLog, db
from flask_jwt_extended import get_jwt_identity

def log_action(actor_id, action, target=None):
    """
    Log an action performed by a user
    
    Parameters:
    - actor_id: ID of the user performing the action
    - action: Description of the action
    - target: Optional target of the action (user, resource, etc.)
    """
    log = ActivityLog(
        actor_id=actor_id,
        action=action,
        target=target
    )
    db.session.add(log)
    db.session.commit() 