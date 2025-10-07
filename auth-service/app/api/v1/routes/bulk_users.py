"""
Bulk user operations API routes
"""

from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional
import uuid

from ...core.security import get_current_admin_user
from ...services.auth_service import AuthService
from ...models.schemas import User

router = APIRouter()

def get_auth_service() -> AuthService:
    return AuthService()


class BulkUserCreateItem(BaseModel):
    email: EmailStr
    display_name: Optional[str] = None
    password: Optional[str] = Field(None, min_length=8)
    is_admin: bool = False


class BulkUserCreateRequest(BaseModel):
    users: List[BulkUserCreateItem] = Field(..., min_items=1, max_items=100)


@router.post("/bulk-create")
async def bulk_create_users(
    request: BulkUserCreateRequest,
    auth_service: AuthService = Depends(get_auth_service),
    current_user: User = Depends(get_current_admin_user)
):
    """Bulk create users (admin only)"""
    try:
        users_data = [user.dict() for user in request.users]
        result = await auth_service.bulk_create_users(users_data, current_user.id)
        
        return {
            "message": f"Bulk user creation completed",
            "success_count": result["success_count"],
            "failure_count": result["failure_count"],
            "created_users": result["created_users"],
            "failed_users": result["failed_users"]
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to bulk create users: {str(e)}"
        )
