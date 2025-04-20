from flask import Blueprint, request, jsonify, url_for
from .models import User, db
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt
from .utils import role_required, admin_required
from .extensions import limiter
import secrets, uuid
from datetime import datetime, timedelta
from .oauth import oauth
from flasgger.utils import swag_from
from flask_limiter.errors import RateLimitExceeded
import logging

logger = logging.getLogger(__name__)

main = Blueprint("main", __name__)
auth_bp = Blueprint("auth", __name__)
admin_bp = Blueprint("admin", __name__)

@main.route("/")
def home():
    return "Welcome to the Authentication System!"

# Register
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
            return jsonify({"error": "Missing JSON"}), 400

        username = data.get("username")
        email = data.get("email")
        password = data.get("password")

        if not username or not email or not password:
            return jsonify({"error": "All fields are required"}), 400

        if User.query.filter_by(email=email).first():
            return jsonify({"error": "Email already registered"}), 400
        if User.query.filter_by(username=username).first():
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
            
            verification_link = url_for('auth.verify_email', token=email_token, _external=True)
            logger.info(f"Verification link generated: {verification_link}")
            
            return jsonify({
                "message": "User registered successfully",
                "verification_link": verification_link
            }), 201
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Database error during registration: {str(e)}")
            return jsonify({"error": "Database error occurred"}), 500
            
    except Exception as e:
        logger.error(f"Registration failed: {str(e)}")
        return jsonify({"error": "Registration failed"}), 500

# Verify Email
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
        
        return jsonify({"message": "Email verified successfully"}), 200
        
    except Exception as e:
        logger.error(f"Email verification failed: {str(e)}")
        return jsonify({"error": "Email verification failed"}), 500

## Login
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
        logger.error(f"Login failed: {str(e)}")
        return jsonify({"error": "Login failed"}), 500

# Final version to paste and use
@auth_bp.route("/verify-2fa-totp", methods=["POST"])
@jwt_required()
def verify_2fa_totp():
    from flask_jwt_extended import get_jwt_identity

    data = request.get_json()
    otp_input = data.get("otp")

    if not otp_input:
        return jsonify({"error": "OTP code is required"}), 400

    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user or not user.totp_secret:
        return jsonify({"error": "TOTP not set up"}), 400

    import pyotp
    totp = pyotp.TOTP(user.totp_secret)

    if totp.verify(otp_input):
        access_token = create_access_token(identity=str(user.id))
        refresh_token = create_refresh_token(identity=str(user.id))
        return jsonify({
            "message": "✅ 2FA verified",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role
            }
        }), 200
    else:
        return jsonify({"error": "❌ Invalid or expired 2FA code"}), 401
    
# Refresh
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
        return jsonify({"access_token": new_access_token}), 200
    except Exception as e:
        logger.error(f"Token refresh failed: {str(e)}")
        return jsonify({"error": "Token refresh failed"}), 500

# Protected
@auth_bp.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    user_id = get_jwt_identity()
    return jsonify({"message": f"Access granted for user ID: {user_id}"}), 200

# Admin
@auth_bp.route("/admin-only", methods=["GET"])
@jwt_required()
@role_required("admin")
def admin_only():
    return jsonify({"message": "Welcome Admin! 🛡️"})

# Forgot Password
@auth_bp.route("/forgot-password", methods=["POST"])
@limiter.limit("3 per minute")
def forgot_password():
    data = request.get_json()
    username = data.get("username")

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    token = str(uuid.uuid4())
    user.reset_token = token
    db.session.commit()

    link = f"http://127.0.0.1:5000/auth/reset-password/{token}"
    print(f"🔁 Simulated password reset link: {link}")

    return jsonify({"message": "Reset link sent (simulated). Check console."}), 200

# Reset Password
@auth_bp.route("/reset-password/<token>", methods=["POST"])
@limiter.limit("3 per minute")
def reset_password(token):
    data = request.get_json()
    new_password = data.get("password")

    user = User.query.filter_by(reset_token=token).first()
    if not user:
        return jsonify({"error": "Invalid or expired token"}), 400

    user.set_password(new_password)
    user.reset_token = None
    db.session.commit()

    return jsonify({"message": "Password has been reset successfully"}), 200

# Change Password
@auth_bp.route("/change-password", methods=["PUT"])
@jwt_required()
def change_password():
    user_id = get_jwt_identity()
    data = request.get_json()

    old_password = data.get("old_password")
    new_password = data.get("new_password")

    user = User.query.get(user_id)
    if not user or not user.check_password(old_password):
        return jsonify({"error": "Invalid old password"}), 401

    user.set_password(new_password)
    db.session.commit()

    return jsonify({"message": "Password changed successfully"}), 200

# Update Username
@auth_bp.route("/update-profile", methods=["PUT"])
@jwt_required()
def update_profile():
    user_id = get_jwt_identity()
    data = request.get_json()
    new_username = data.get("username")

    if not new_username:
        return jsonify({"error": "New username is required"}), 400

    if User.query.filter_by(username=new_username).first():
        return jsonify({"error": "Username already taken"}), 400

    user = User.query.get(user_id)
    user.username = new_username
    db.session.commit()

    return jsonify({"message": "Username updated successfully"}), 200

@admin_bp.route("/admin/users", methods=["GET"])
@jwt_required()
@admin_required
def get_all_users():
    users = User.query.all()
    data = []
    for user in users:
        data.append({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "roles": [role.name for role in user.roles],
            "is_active": user.is_active,
            "created_at": user.created_at,
            "updated_at": user.updated_at
        })
    return jsonify(data), 200

import pyotp
import qrcode
import io
from flask import send_file

@auth_bp.route("/enable-2fa-totp", methods=["GET"])
@jwt_required()
def enable_2fa_totp():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    # 1. Generate new TOTP secret
    secret = pyotp.random_base32()
    user.totp_secret = secret
    db.session.commit()

    # 2. Create OTP Auth URL (compatible with Authenticator app)
    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="FlaskAuthApp")

    # 3. Generate QR code
    qr = qrcode.make(otp_uri)
    buf = io.BytesIO()
    qr.save(buf)
    buf.seek(0)

    return send_file(buf, mimetype='image/png')

@auth_bp.route('/auth/google')
def google_login():
    # Generate the redirect URI for the callback endpoint
    redirect_uri = url_for('auth.google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@auth_bp.route('/auth/google/callback')
def google_callback():
    # Retrieve the token and user info from Google
    token = oauth.google.authorize_access_token()
    user_info = oauth.google.parse_id_token(token)
    email = user_info.get('email')

    # Check if user exists in our DB
    user = User.query.filter_by(email=email).first()
    if not user:
        # Auto-register the user if not found
        user = User(
            email=email,
            username=email.split("@")[0],
            password="OAuth_Login",  # Dummy value, as password is not used
            is_active=True
        )
        db.session.add(user)
        db.session.commit()

    # Create JWT tokens for your app
    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))

    return jsonify({
        "message": "Logged in with Google",
        "access_token": access_token,
        "refresh_token": refresh_token,
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role
        }
    })

# =========================
# 🚪 Logout
# =========================
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
        # Add token to blacklist
        # This is handled by your token blacklist mechanism
        return jsonify({"message": "Successfully logged out"}), 200
    except Exception as e:
        logger.error(f"Logout failed: {str(e)}")
        return jsonify({"error": "Logout failed"}), 500

# =========================
# ⚠️ Rate Limit Error Handler
# =========================
@auth_bp.errorhandler(RateLimitExceeded)
def handle_rate_limit_exceeded(e):
    return jsonify({"error": "Rate limit exceeded"}), 429