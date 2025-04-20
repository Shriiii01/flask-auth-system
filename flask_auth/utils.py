from functools import wraps
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, get_jwt
from flask import jsonify
from .models import User

def role_required(required_role):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            jwt_data = get_jwt()
            
            # Check if token has been revoked
            if not user or str(user.token_revoked_at) != jwt_data.get("token_issued_at"):
                return jsonify({"error": "Token has been revoked"}), 401

            if user and any(role.name == required_role for role in user.roles):
                return fn(*args, **kwargs)
            else:
                return jsonify({"error": f"Forbidden: {required_role} role required"}), 403
        return decorator
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        jwt_data = get_jwt()
        
        # Check if token has been revoked
        if not user or str(user.token_revoked_at) != jwt_data.get("token_issued_at"):
            return jsonify({"error": "Token has been revoked"}), 401
            
        if not user or not any(role.name == "admin" for role in user.roles):
            return jsonify({"error": "Admin access required"}), 403
        return fn(*args, **kwargs)
    return wrapper
