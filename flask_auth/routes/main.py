from fastapi import APIRouter, Depends
from ..utils.jwt import get_current_active_user
from ..models import User
from ..extensions import logger

router = APIRouter()

@router.get(
    "/",
    summary="Home endpoint",
    description="Returns a welcome message. Requires authentication.",
    responses={
        200: {
            "description": "Welcome message",
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "message": {
                                "type": "string",
                                "example": "Welcome to the Authentication System!"
                            }
                        }
                    }
                }
            }
        },
        401: {
            "description": "Unauthorized"
        }
    }
)
async def home(current_user: User = Depends(get_current_active_user)):
    try:
        logger.info("Home endpoint accessed")
        return {
            "message": "Welcome to the Authentication System!"
        }
    except Exception as e:
        logger.error(f"Error in home endpoint: {str(e)}")
        return {
            "error": "Internal server error"
        } 