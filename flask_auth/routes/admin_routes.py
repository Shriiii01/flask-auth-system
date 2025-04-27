from flask import Blueprint, request, jsonify
from ..models import User, Role, ActivityLog, db
from flask_jwt_extended import jwt_required, get_jwt_identity
from ..utils import role_required, admin_required
from ..utils.logger import log_action
from ..extensions import logger
from flasgger.utils import swag_from
import traceback

admin_bp = Blueprint("admin", __name__)

@admin_bp.route("/roles", methods=["POST"])
@jwt_required()
@role_required("admin")
@swag_from({
    'tags': ['Admin'],
    'security': [{'BearerAuth': []}],
    'summary': 'Create new role',
    'description': 'Creates a new role in the system',
    'requestBody': {
        'required': True,
        'content': {
            'application/json': {
                'schema': {
                    'type': 'object',
                    'required': ['name'],
                    'properties': {
                        'name': {'type': 'string', 'example': 'editor'},
                        'description': {'type': 'string', 'example': 'Can edit content'}
                    }
                }
            }
        }
    },
    'responses': {
        201: {
            'description': 'Role created successfully',
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
        }
    }
})
def create_role():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing JSON"}), 400

        name = data.get("name")
        description = data.get("description", "")

        if not name:
            return jsonify({"error": "Role name is required"}), 400

        if Role.query.filter_by(name=name).first():
            return jsonify({"error": "Role already exists"}), 400

        new_role = Role(name=name)
        if hasattr(Role, 'description'):
            new_role.description = description

        db.session.add(new_role)
        db.session.commit()
        
        log_action(actor_id=get_jwt_identity(), action=f"Created role '{name}'")
        logger.info(f"Role created successfully: {name}")
        
        return jsonify({"message": f"Role '{name}' created successfully"}), 201

    except Exception as e:
        logger.error(f"Role creation failed: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "Failed to create role"}), 500

@admin_bp.route("/roles", methods=["GET"])
@jwt_required()
@role_required("admin")
@swag_from({
    'tags': ['Admin'],
    'security': [{'BearerAuth': []}],
    'summary': 'List all roles',
    'description': 'Returns a list of all roles in the system',
    'responses': {
        200: {
            'description': 'List of roles',
            'content': {
                'application/json': {
                    'schema': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'properties': {
                                'id': {'type': 'integer'},
                                'name': {'type': 'string'},
                                'description': {'type': 'string'}
                            }
                        }
                    }
                }
            }
        }
    }
})
def list_roles():
    try:
        roles = Role.query.all()
        if hasattr(Role, 'description'):
            return jsonify([{
                "id": r.id,
                "name": r.name,
                "description": r.description
            } for r in roles]), 200
        else:
            return jsonify([{
                "id": r.id,
                "name": r.name
            } for r in roles]), 200
    except Exception as e:
        logger.error(f"Failed to list roles: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "Failed to retrieve roles"}), 500

@admin_bp.route("/users/<int:user_id>/roles", methods=["POST"])
@jwt_required()
@role_required("admin")
@swag_from({
    'tags': ['Admin'],
    'security': [{'BearerAuth': []}],
    'summary': 'Assign role to user',
    'description': 'Assigns a role to a specific user',
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
                    'required': ['role'],
                    'properties': {
                        'role': {'type': 'string', 'example': 'editor'}
                    }
                }
            }
        }
    },
    'responses': {
        200: {
            'description': 'Role assigned successfully',
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
            'description': 'User or role not found',
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
def assign_role(user_id):
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing JSON"}), 400

        role_name = data.get("role")
        if not role_name:
            return jsonify({"error": "Role name is required"}), 400
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            return jsonify({"error": "Role not found"}), 404
            
        if role in user.roles:
            return jsonify({"error": "User already has this role"}), 400
            
        user.roles.append(role)
        db.session.commit()
        
        log_action(
            actor_id=get_jwt_identity(),
            action=f"Assigned role '{role_name}' to user {user.username}"
        )
        logger.info(f"Role '{role_name}' assigned to user {user.username}")
        
        return jsonify({"message": f"Role '{role_name}' assigned to user successfully"}), 200

    except Exception as e:
        logger.error(f"Role assignment failed: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "Failed to assign role"}), 500

@admin_bp.route("/users/<int:user_id>/roles", methods=["DELETE"])
@jwt_required()
@role_required("admin")
@swag_from({
    'tags': ['Admin'],
    'security': [{'BearerAuth': []}],
    'summary': 'Remove role from user',
    'description': 'Removes a role from a specific user',
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
                    'required': ['role'],
                    'properties': {
                        'role': {'type': 'string', 'example': 'editor'}
                    }
                }
            }
        }
    },
    'responses': {
        200: {
            'description': 'Role removed successfully',
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
            'description': 'User or role not found',
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
def remove_role(user_id):
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing JSON"}), 400

        role_name = data.get("role")
        if not role_name:
            return jsonify({"error": "Role name is required"}), 400
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
            
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            return jsonify({"error": "Role not found"}), 404
            
        if role not in user.roles:
            return jsonify({"error": "User does not have this role"}), 400
            
        user.roles.remove(role)
        db.session.commit()
        
        log_action(
            actor_id=get_jwt_identity(),
            action=f"Removed role '{role_name}' from user {user.username}"
        )
        logger.info(f"Role '{role_name}' removed from user {user.username}")
        
        return jsonify({"message": f"Role '{role_name}' removed from user successfully"}), 200

    except Exception as e:
        logger.error(f"Role removal failed: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "Failed to remove role"}), 500

@admin_bp.route("/roles/<int:role_id>", methods=["DELETE"])
@jwt_required()
@role_required("admin")
@swag_from({
    'tags': ['Admin'],
    'security': [{'BearerAuth': []}],
    'summary': 'Delete role',
    'description': 'Deletes a role from the system',
    'parameters': [
        {
            'name': 'role_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'Role ID'
        }
    ],
    'responses': {
        200: {
            'description': 'Role deleted successfully',
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
            'description': 'Role not found',
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
def delete_role(role_id):
    try:
        role = Role.query.get(role_id)
        if not role:
            return jsonify({"error": "Role not found"}), 404
            
        if role.name == "admin":
            return jsonify({"error": "Cannot delete admin role"}), 400
            
        db.session.delete(role)
        db.session.commit()
        
        log_action(actor_id=get_jwt_identity(), action=f"Deleted role '{role.name}'")
        logger.info(f"Role '{role.name}' deleted successfully")
        
        return jsonify({"message": f"Role '{role.name}' deleted successfully"}), 200

    except Exception as e:
        logger.error(f"Role deletion failed: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "Failed to delete role"}), 500

@admin_bp.route("/activity-logs", methods=["GET"])
@jwt_required()
@role_required("admin")
@swag_from({
    'tags': ['Admin'],
    'security': [{'BearerAuth': []}],
    'summary': 'Get activity logs',
    'description': 'Returns a list of activity logs',
    'parameters': [
        {
            'name': 'limit',
            'in': 'query',
            'type': 'integer',
            'required': False,
            'description': 'Number of logs to return',
            'default': 50
        }
    ],
    'responses': {
        200: {
            'description': 'List of activity logs',
            'content': {
                'application/json': {
                    'schema': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'properties': {
                                'id': {'type': 'integer'},
                                'actor_id': {'type': 'integer'},
                                'action': {'type': 'string'},
                                'target': {'type': 'string'},
                                'timestamp': {'type': 'string', 'format': 'date-time'}
                            }
                        }
                    }
                }
            }
        }
    }
})
def get_logs():
    try:
        limit = request.args.get('limit', 50, type=int)
        logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(limit).all()
        
        return jsonify([{
            "id": log.id,
            "actor_id": log.actor_id,
            "action": log.action,
            "target": log.target,
            "timestamp": log.timestamp.isoformat()
        } for log in logs]), 200
        
    except Exception as e:
        logger.error(f"Failed to retrieve activity logs: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "Failed to retrieve activity logs"}), 500