from authlib.integrations.httpx_client import AsyncOAuth2Client
from config import Config

def get_google_oauth_client():
    return AsyncOAuth2Client(
        client_id=Config.GOOGLE_CLIENT_ID,
        client_secret=Config.GOOGLE_CLIENT_SECRET,
        scope='openid email profile'
    )

def get_github_oauth_client():
    return AsyncOAuth2Client(
        client_id=Config.GITHUB_CLIENT_ID,
        client_secret=Config.GITHUB_CLIENT_SECRET,
        scope='user:email'
    )

