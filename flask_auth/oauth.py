from authlib.integrations.httpx_client import AsyncOAuth2Client
import os
from config import Config

oauth_client = None

def configure_oauth(app):
    global oauth_client
    oauth_client = AsyncOAuth2Client(
        client_id=Config.GITHUB_CLIENT_ID,
        client_secret=Config.GITHUB_CLIENT_SECRET,
        scope='user:email'
    )

def get_github_oauth_client():
    return AsyncOAuth2Client(
        client_id=Config.GITHUB_CLIENT_ID,
        client_secret=Config.GITHUB_CLIENT_SECRET,
        scope='user:email'
    )

