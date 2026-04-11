from slowapi import Limiter
from slowapi.util import get_remote_address
import redis
import logging
import os

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

redis_host = os.getenv('REDIS_HOST', 'localhost')
redis_port = int(os.getenv('REDIS_PORT', 6379))

redis_client = None
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
    logger.warning(f"Redis unavailable, using in-memory fallback: {e}")
    redis_client = None

# In-memory blacklist fallback when Redis is not available
_memory_blacklist: set = set()

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=f"redis://{redis_host}:{redis_port}" if redis_client else "memory://",
    default_limits=["1000 per day", "100 per hour"]
)


def blacklist_token(token: str, expires_in_seconds: int = 3600) -> None:
    """Add a token to the blacklist so it can no longer be used after logout."""
    if redis_client:
        redis_client.setex(f"blacklist:{token}", expires_in_seconds, "1")
    else:
        _memory_blacklist.add(token)


def is_token_blacklisted(token: str) -> bool:
    """Return True if the token has been revoked via logout."""
    if redis_client:
        return redis_client.exists(f"blacklist:{token}") == 1
    return token in _memory_blacklist
