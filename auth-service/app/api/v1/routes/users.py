"""
User management API routes
"""

from fastapi import APIRouter, HTTPException, Depends, Query, status
from typing import Optional, List
import uuid

from ...core.security import get_current_admin_user
from ...services.auth_service import AuthService
from ...models.schemas import (
    User,
    PaginatedResponse,
    UserFilters,
    CreateUserRequest,
    UpdateUserRequest
)

router = APIRouter()

def get_auth_service() -> AuthService:
    return AuthService()


@router.get("/", response_model=PaginatedResponse[User])
async def get_users(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = Query(None),
    is_approved: Optional[bool] = Query(None),
    provider: Optional[str] = Query(None),
    auth_service: AuthService = Depends(get_auth_service),
    current_user: User = Depends(get_current_admin_user)
):
    """Get paginated list of users (admin only)"""
    filters = UserFilters(
        search=search,
        is_approved=is_approved,
        provider=provider,
        page=page,
        limit=limit
    )
    
    try:
        result = await auth_service.get_users(filters)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve users"
        )


@router.get("/{user_id}", response_model=User)
async def get_user(
    user_id: uuid.UUID,
    auth_service: AuthService = Depends(get_auth_service),
    current_user: User = Depends(get_current_admin_user)
):
    """Get user by ID (admin only)"""
    try:
        user = await auth_service.get_user_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        return user
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user"
        )


@router.post("/", response_model=User)
async def create_user(
    request: CreateUserRequest,
    auth_service: AuthService = Depends(get_auth_service),
    current_user: User = Depends(get_current_admin_user)
):
    """Create a new user manually (admin only)"""
    try:
        user = await auth_service.create_user_manually(
            email=request.email,
            display_name=request.display_name,
            password=request.password,
            is_admin=request.is_admin,
            created_by=current_user.id
        )
        return user
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create user"
        )


@router.put("/{user_id}", response_model=User)
async def update_user(
    user_id: uuid.UUID,
    request: UpdateUserRequest,
    auth_service: AuthService = Depends(get_auth_service),
    current_user: User = Depends(get_current_admin_user)
):
    """Update user (admin only)"""
    try:
        user = await auth_service.update_user(
            user_id=user_id,
            display_name=request.display_name,
            is_admin=request.is_admin,
            is_approved=request.is_approved,
            updated_by=current_user.id
        )
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return user
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user"
        )


@router.delete("/{user_id}")
async def delete_user(
    user_id: uuid.UUID,
    auth_service: AuthService = Depends(get_auth_service),
    current_user: User = Depends(get_current_admin_user)
):
    """Delete user (admin only)"""
    try:
        success = await auth_service.delete_user(user_id, deleted_by=current_user.id)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        return {"message": "User deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete user"
        )


@router.post("/{user_id}/link-provider")
async def link_provider(
    user_id: uuid.UUID,
    provider: str,
    auth_service: AuthService = Depends(get_auth_service),
    current_user: User = Depends(get_current_admin_user)
):
    """Link authentication provider to user (admin only)"""
    try:
        result = await auth_service.link_provider_to_user(
            user_id=user_id,
            provider=provider
        )
        
        if not result.success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error_message
            )
        
        return {"message": f"Provider {provider} linked successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to link provider"
        )


@router.delete("/{user_id}/unlink-provider/{provider}")
async def unlink_provider(
    user_id: uuid.UUID,
    provider: str,
    auth_service: AuthService = Depends(get_auth_service),
    current_user: User = Depends(get_current_admin_user)
):
    """Unlink authentication provider from user (admin only)"""
    try:
        result = await auth_service.unlink_provider_from_user(
            user_id=user_id,
            provider=provider
        )
        
        if not result.success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error_message
            )
        
        return {"message": f"Provider {provider} unlinked successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to unlink provider"
        )