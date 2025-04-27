from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from .extensions import limiter
from .oauth import configure_oauth
from flasgger import Swagger

db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()

def create_app():
    app = Flask(__name__)
    app.config.from_object("config.Config")

    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    limiter.init_app(app)
    configure_oauth(app)
    
    CORS(app, resources={
        r"/*": {
            "origins": "*",
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"]
        }
    })

    app.config['RATELIMIT_HEADERS_ENABLED'] = True
    
    if app.config.get('ENV') == 'development':
        limiter.enabled = False

    from .routes.auth import auth_bp
    from .routes.main import main_bp
    from .routes.admin_routes import admin_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp, url_prefix="/admin")

    swagger_config = {
        "headers": [],
        "specs": [
            {
                "endpoint": 'apispec',
                "route": '/apispec.json',
                "rule_filter": lambda rule: True,
                "model_filter": lambda tag: True,
            }
        ],
        "static_url_path": "/flasgger_static",
        "swagger_ui": True,
        "specs_route": "/docs",
        "swagger_ui_bundle_js": "https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.9.0/swagger-ui-bundle.min.js",
        "swagger_ui_standalone_preset_js": "https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.9.0/swagger-ui-standalone-preset.min.js",
        "swagger_ui_css": "https://cdnjs.cloudflare.com/ajax/libs/swagger-ui/5.9.0/swagger-ui.min.css",
        "swagger_ui_config": {
            "deepLinking": True,
            "persistAuthorization": True,
            "displayOperationId": True,
            "defaultModelsExpandDepth": 3,
            "defaultModelExpandDepth": 3,
            "defaultModelRendering": "model",
            "displayRequestDuration": True,
            "docExpansion": "list",
            "filter": True,
            "showExtensions": True,
            "showCommonExtensions": True,
            "tryItOutEnabled": True,
            "supportedSubmitMethods": ["get", "put", "post", "delete", "options", "head", "patch", "trace"]
        }
    }

    swagger_template = {
        "swagger": "2.0",
        "info": {
            "title": "Authentication API",
            "description": "Full-featured Flask Auth System with JWT, OAuth, and Role-based Access Control",
            "version": "1.0",
            "contact": {
                "name": "API Support",
                "email": app.config.get('EMAIL_SENDER', 'support@example.com')
            }
        },
        "securityDefinitions": {
            "BearerAuth": {
                "type": "apiKey",
                "name": "Authorization",
                "in": "header",
                "description": "JWT Authorization header using the Bearer scheme. Example: 'Bearer {token}'"
            }
        },
        "security": [{"BearerAuth": []}],
        "schemes": ["http", "https"],
        "consumes": ["application/json"],
        "produces": ["application/json"],
        "host": "localhost:5001",
        "basePath": "/"
    }

    Swagger(app, config=swagger_config, template=swagger_template)

    return app