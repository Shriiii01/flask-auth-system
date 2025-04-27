from flask import Blueprint, request, jsonify, url_for, current_app
from ..models import User, db
from flask_jwt_extended import (
    create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from ..utils import role_required
from ..extensions import limiter, logger
from ..oauth import oauth
from flasgger.utils import swag_from
from flask_limiter.errors import RateLimitExceeded
import secrets, traceback
from datetime import datetime, timedelta

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/register", methods=["POST"])
@limiter.limit("3 per minute")
@swag_from({
    'tags': ['Authentication'],
    'summary': 'Register a new user',
    'description': 'Creates a new user account and sends a verification email',
    'requestBody': {
        'required': True,
        'content': {
            'application/json': {
                'schema': {
                    'type': 'object',
                    'required': ['username', 'email', 'password'],
                    'properties': {
                        'username': {'type': 'string', 'example': 'johndoe'},
                        'email': {'type': 'string', 'format': 'email', 'example': 'john@example.com'},
                        'password': {'type': 'string', 'format': 'password', 'example': 'strongpass123'}
                    }
                }
            }
        }
    },
    'responses': {
        201: {
            'description': 'User registered successfully',
            'content': {
                'application/json': {
                    'schema': {
                        'type': 'object',
                        'properties': {
                            'message': {'type': 'string'},
                            'verification_link': {'type': 'string'}
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
def register():
    try:
        data = request.get_json()
        if not data:
            logger.warning("Registration attempt with missing JSON data")
            return jsonify({"error": "Missing JSON"}), 400

        username = data.get("username")
        email = data.get("email")
        password = data.get("password")

        logger.debug(f"Registration attempt for username: {username}, email: {email}")

        if not username or not email or not password:
            logger.warning("Registration attempt with missing required fields")
            return jsonify({"error": "All fields are required"}), 400

        if User.query.filter_by(email=email).first():
            logger.warning(f"Registration attempt with existing email: {email}")
            return jsonify({"error": "Email already registered"}), 400
            
        if User.query.filter_by(username=username).first():
            logger.warning(f"Registration attempt with existing username: {username}")
            return jsonify({"error": "Username already taken"}), 400

        email_token = secrets.token_urlsafe(32)
        new_user = User(
            username=username,
            email=email,
            email_verification_token=email_token,
            is_active=True,
            is_verified=False
        )
        new_user.set_password(password)

        try:
            db.session.add(new_user)
            db.session.commit()
            logger.info(f"Successfully registered new user: {username}")
            
            verification_link = url_for('auth.verify_email', token=email_token, _external=True)
            
            return jsonify({
                "message": "User registered successfully",
                "verification_link": verification_link
            }), 201
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Database error during registration: {str(e)}\n{traceback.format_exc()}")
            return jsonify({"error": "Database error occurred"}), 500
            
    except Exception as e:
        logger.error(f"Registration failed: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "Registration failed"}), 500

@auth_bp.route("/verify-email/<token>", methods=["GET"])
@swag_from({
    'tags': ['Authentication'],
    'summary': 'Verify email address',
    'description': 'Verifies a user\'s email address using the token sent during registration',
    'parameters': [
        {
            'name': 'token',
            'in': 'path',
            'type': 'string',
            'required': True,
            'description': 'Email verification token'
        }
    ],
    'responses': {
        200: {
            'description': 'Email verified successfully',
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
            'description': 'Invalid or expired token',
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
def verify_email(token):
    try:
        user = User.query.filter_by(email_verification_token=token).first()
        if not user:
            return jsonify({"error": "Invalid verification token"}), 400
            
        user.is_verified = True
        user.email_verification_token = None
        db.session.commit()
        logger.info(f"Email verified successfully for user: {user.username}")
        
        return jsonify({"message": "Email verified successfully"}), 200
        
    except Exception as e:
        logger.error(f"Email verification failed: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "Email verification failed"}), 500

@auth_bp.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
@swag_from({
    'tags': ['Authentication'],
    'summary': 'Login user',
    'description': 'Authenticates a user and returns JWT tokens',
    'requestBody': {
        'required': True,
        'content': {
            'application/json': {
                'schema': {
                    'type': 'object',
                    'required': ['email', 'password'],
                    'properties': {
                        'email': {'type': 'string', 'format': 'email', 'example': 'john@example.com'},
                        'password': {'type': 'string', 'format': 'password', 'example': 'strongpass123'}
                    }
                }
            }
        }
    },
    'responses': {
        200: {
            'description': 'Login successful',
            'content': {
                'application/json': {
                    'schema': {
                        'type': 'object',
                        'properties': {
                            'access_token': {'type': 'string'},
                            'refresh_token': {'type': 'string'},
                            'user': {
                                'type': 'object',
                                'properties': {
                                    'id': {'type': 'integer'},
                                    'username': {'type': 'string'},
                                    'email': {'type': 'string'},
                                    'roles': {'type': 'array', 'items': {'type': 'string'}}
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
        401: {
            'description': 'Invalid credentials',
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
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing JSON"}), 400

        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400

        user = User.query.filter_by(email=email).first()
        if not user or not user.check_password(password):
            return jsonify({"error": "Invalid email or password"}), 401

        if not user.is_active:
            return jsonify({"error": "Account is deactivated"}), 401

        if not user.is_verified:
            return jsonify({"error": "Email not verified"}), 401

        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        logger.info(f"User logged in successfully: {user.username}")

        return jsonify({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "roles": [role.name for role in user.roles]
            }
        }), 200

    except Exception as e:
        logger.error(f"Login failed: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "Login failed"}), 500

@auth_bp.route("/logout", methods=["POST"])
@jwt_required()
@swag_from({
    'tags': ['Authentication'],
    'summary': 'Logout user',
    'description': 'Invalidates the current JWT token',
    'security': [{'BearerAuth': []}],
    'responses': {
        200: {
            'description': 'Logged out successfully',
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
        401: {
            'description': 'Invalid token',
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
def logout():
    try:
        jti = get_jwt()["jti"]
        logger.info(f"User logged out successfully: {get_jwt_identity()}")
        return jsonify({"message": "Successfully logged out"}), 200
    except Exception as e:
        logger.error(f"Logout failed: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "Logout failed"}), 500

@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
@swag_from({
    'tags': ['Authentication'],
    'summary': 'Refresh access token',
    'description': 'Get a new access token using a refresh token',
    'security': [{'BearerAuth': []}],
    'responses': {
        200: {
            'description': 'New access token generated',
            'content': {
                'application/json': {
                    'schema': {
                        'type': 'object',
                        'properties': {
                            'access_token': {'type': 'string'}
                        }
                    }
                }
            }
        },
        401: {
            'description': 'Invalid refresh token',
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
def refresh():
    try:
        current_user = get_jwt_identity()
        new_access_token = create_access_token(identity=current_user)
        logger.info(f"Access token refreshed for user ID: {current_user}")
        return jsonify({"access_token": new_access_token}), 200
    except Exception as e:
        logger.error(f"Token refresh failed: {str(e)}\n{traceback.format_exc()}")
        return jsonify({"error": "Token refresh failed"}), 500

@auth_bp.errorhandler(429)
def handle_rate_limit_exceeded(e):
    return jsonify({"error": "Rate limit exceeded"}), 429