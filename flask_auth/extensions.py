from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis
import logging
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
cors = CORS()
bcrypt = Bcrypt()

# Configure Redis
redis_client = None
redis_host = os.getenv('REDIS_HOST', 'localhost')
redis_port = int(os.getenv('REDIS_PORT', 6379))

try:
    redis_client = redis.Redis(
        host=redis_host,
        port=redis_port,
        db=0,
        decode_responses=True,
        socket_timeout=5,
        socket_connect_timeout=5
    )
    redis_client.ping()
    logger.info("Redis connection successful")
except (redis.ConnectionError, redis.TimeoutError) as e:
    logger.warning(f"Redis connection failed: {str(e)}")
    redis_client = None

# Initialize rate limiter with Redis if available, otherwise use in-memory storage
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=f"redis://{redis_host}:{redis_port}" if redis_client else "memory://",
    default_limits=["200 per day", "50 per hour"],
    strategy="fixed-window"
)

def init_extensions(app):
    """Initialize all Flask extensions"""
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    cors.init_app(app)
    bcrypt.init_app(app)
    limiter.init_app(app)
    logger.info("All extensions initialized successfully")