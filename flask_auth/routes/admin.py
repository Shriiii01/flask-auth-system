from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from ..models import User, Role, db
from ..utils import admin_required
from datetime import datetime
from flasgger.utils import swag_from

admin_bp = Blueprint("admin", __name__)

@admin_bp.route("/users", methods=["GET"])
@jwt_required()
@admin_required
@swag_from({
    'tags': ['Admin'],
    'security': [{'BearerAuth': []}],
    'summary': 'Get all users',
    'description': 'Retrieves a list of all users in the system',
    'responses': {
        200: {
            'description': 'List of users',
            'content': {
                'application/json': {
                    'schema': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'properties': {
                                'id': {'type': 'integer'},
                                'username': {'type': 'string'},
                                'email': {'type': 'string'},
                                'roles': {'type': 'array', 'items': {'type': 'string'}},
                                'is_active': {'type': 'boolean'},
                                'created_at': {'type': 'string', 'format': 'date-time'},
                                'updated_at': {'type': 'string', 'format': 'date-time'}
                            }
                        }
                    }
                }
            }
        },
        401: {
            'description': 'Unauthorized',
            'content': {
                'application/json': {
                    'schema': {
                        'type': 'object',
                        'properties': {
                            'error': {'type': 'string'}
                        }
                    }
                }
            }
        }
    }
})
def get_all_users():
    users = User.query.all()
    return jsonify([{
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "roles": [role.name for role in user.roles],
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "updated_at": user.updated_at.isoformat() if user.updated_at else None
    } for user in users]), 200

@admin_bp.route("/users/<int:user_id>", methods=["PUT"])
@jwt_required()
@admin_required
@swag_from({
    'tags': ['Admin'],
    'security': [{'BearerAuth': []}],
    'summary': 'Update user',
    'description': 'Update user details including username, email, active status, and roles',
    'parameters': [
        {
            'name': 'user_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'User ID'
        }
    ],
    'requestBody': {
        'required': True,
        'content': {
            'application/json': {
                'schema': {
                    'type': 'object',
                    'properties': {
                        'username': {'type': 'string', 'example': 'newusername'},
                        'email': {'type': 'string', 'format': 'email', 'example': 'newemail@example.com'},
                        'is_active': {'type': 'boolean', 'example': True},
                        'roles': {'type': 'array', 'items': {'type': 'string'}, 'example': ['admin', 'editor']}
                    }
                }
            }
        }
    },
    'responses': {
        200: {
            'description': 'User updated successfully',
            'content': {
                'application/json': {
                    'schema': {
                        'type': 'object',
                        'properties': {
                            'message': {'type': 'string'},
                            'user': {
                                'type': 'object',
                                'properties': {
                                    'id': {'type': 'integer'},
                                    'username': {'type': 'string'},
                                    'email': {'type': 'string'},
                                    'roles': {'type': 'array', 'items': {'type': 'string'}},
                                    'is_active': {'type': 'boolean'}
                                }
                            }
                        }
                    }
                }
            }
        },
        400: {
            'description': 'Bad request',
            'content': {
                'application/json': {
                    'schema': {
                        'type': 'object',
                        'properties': {
                            'error': {'type': 'string'}
                        }
                    }
                }
            }
        },
        404: {
            'description': 'User not found',
            'content': {
                'application/json': {
                    'schema': {
                        'type': 'object',
                        'properties': {
                            'error': {'type': 'string'}
                        }
                    }
                }
            }
        }
    }
})
def update_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json()
    if "username" in data:
        if User.query.filter_by(username=data["username"]).first():
            return jsonify({"error": "Username already taken"}), 400
        user.username = data["username"]
    
    if "email" in data:
        if User.query.filter_by(email=data["email"]).first():
            return jsonify({"error": "Email already in use"}), 400
        user.email = data["email"]
    
    if "is_active" in data:
        user.is_active = data["is_active"]
    
    if "roles" in data:
        user.roles = [Role.query.filter_by(name=role_name).first() for role_name in data["roles"]]
    
    user.updated_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({
        "message": "User updated successfully",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "roles": [role.name for role in user.roles],
            "is_active": user.is_active
        }
    }), 200

@admin_bp.route("/users/<int:user_id>", methods=["DELETE"])
@jwt_required()
@admin_required
@swag_from({
    'tags': ['Admin'],
    'security': [{'BearerAuth': []}],
    'summary': 'Delete user',
    'description': 'Delete a user from the system',
    'parameters': [
        {
            'name': 'user_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'User ID'
        }
    ],
    'responses': {
        200: {
            'description': 'User deleted successfully',
            'content': {
                'application/json': {
                    'schema': {
                        'type': 'object',
                        'properties': {
                            'message': {'type': 'string'}
                        }
                    }
                }
            }
        },
        404: {
            'description': 'User not found',
            'content': {
                'application/json': {
                    'schema': {
                        'type': 'object',
                        'properties': {
                            'error': {'type': 'string'}
                        }
                    }
                }
            }
        }
    }
})
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({"message": "User deleted successfully"}), 200 