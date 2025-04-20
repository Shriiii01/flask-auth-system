from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required
from flasgger.utils import swag_from
from ..extensions import logger

main_bp = Blueprint("main", __name__)

@main_bp.route("/", methods=["GET"])
@jwt_required()
@swag_from({
    'tags': ['Main'],
    'security': [{'BearerAuth': []}],
    'summary': 'Home endpoint',
    'description': 'Returns a welcome message. Requires authentication.',
    'responses': {
        200: {
            'description': 'Welcome message',
            'content': {
                'application/json': {
                    'schema': {
                        'type': 'object',
                        'properties': {
                            'message': {
                                'type': 'string',
                                'example': 'Welcome to the Authentication System!'
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
                            'msg': {
                                'type': 'string',
                                'example': 'Missing Authorization Header'
                            }
                        }
                    }
                }
            }
        }
    }
})
def home():
    try:
        logger.info("Home endpoint accessed")
        return jsonify({
            "message": "Welcome to the Authentication System!"
        }), 200
    except Exception as e:
        logger.error(f"Error in home endpoint: {str(e)}")
        return jsonify({
            "error": "Internal server error"
        }), 500 