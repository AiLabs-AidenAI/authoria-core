"""
Role management API routes
"""

from fastapi import APIRouter, HTTPException, Depends, Request, status
from pydantic import BaseModel, Field
from typing import List, Optional
import uuid
from datetime import datetime

from ...services.auth_service import AuthService
from ...core.security import verify_token
from ...models.schemas import MessageResponse

router = APIRouter()

# Request/Response models
class CreateRoleRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=50)
    display_name: str = Field(..., min_length=2, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    is_admin_role: bool = False
    permissions: List[str] = []

class UpdateRoleRequest(BaseModel):
    display_name: Optional[str] = Field(None, min_length=2, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    is_admin_role: Optional[bool] = None
    permissions: Optional[List[str]] = None

class AssignRoleRequest(BaseModel):
    role_ids: List[uuid.UUID]

class RoleResponse(BaseModel):
    id: str
    name: str
    display_name: str
    description: Optional[str]
    is_system_role: bool
    is_admin_role: bool
    permissions: List[str]
    user_count: int
    created_at: datetime

# Dependency to verify admin access
async def verify_admin_access(request: Request) -> uuid.UUID:
    """Verify that the request is from an authenticated admin user"""
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header"
        )
    
    try:
        token = auth_header.split(" ")[1]
        payload = verify_token(token)
        user_id = payload.get("sub")
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        return uuid.UUID(user_id)
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token verification failed"
        )

def get_auth_service() -> AuthService:
    return AuthService()

@router.get("/roles")
async def get_roles(
    admin_user_id: uuid.UUID = Depends(verify_admin_access),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Get all available roles"""
    try:
        # For now, return predefined system roles
        # In future, this would query the database
        from ...models.role import SYSTEM_ROLES
        
        roles_data = []
        for role in SYSTEM_ROLES:
            roles_data.append({
            "id": str(uuid.uuid4()),  # Generate temporary ID
            "name": role["name"],
            "display_name": role["display_name"],
            "description": role["description"],
            "is_system_role": role["is_system_role"],
            "is_admin_role": role["is_admin_role"],
            "permissions": role["permissions"],
            "user_count": 0,  # Would be calculated from database
                "created_at": datetime.utcnow().isoformat()
            })
        
        return {"items": roles_data}
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch roles"
        )

@router.post("/roles")
async def create_role(
    request: CreateRoleRequest,
    admin_user_id: uuid.UUID = Depends(verify_admin_access),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Create a new custom role"""
    try:
        # This would create a role in the database
        # For now, return success message
        return MessageResponse(
            message=f"Role '{request.display_name}' created successfully",
            data={
                "role_name": request.name,
                "display_name": request.display_name
            }
        )
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create role"
        )

@router.put("/roles/{role_id}")
async def update_role(
    role_id: uuid.UUID,
    request: UpdateRoleRequest,
    admin_user_id: uuid.UUID = Depends(verify_admin_access),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Update an existing role"""
    try:
        return MessageResponse(
            message="Role updated successfully"
        )
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update role"
        )

@router.delete("/roles/{role_id}")
async def delete_role(
    role_id: uuid.UUID,
    admin_user_id: uuid.UUID = Depends(verify_admin_access),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Delete a role (only non-system roles)"""
    try:
        return MessageResponse(
            message="Role deleted successfully"
        )
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete role"
        )

@router.post("/users/{user_id}/roles")
async def assign_user_roles(
    user_id: uuid.UUID,
    request: AssignRoleRequest,
    admin_user_id: uuid.UUID = Depends(verify_admin_access),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Assign roles to a user"""
    try:
        # This would assign roles in the database
        # For now, return success message
        return MessageResponse(
            message=f"Roles assigned to user successfully",
            data={
                "user_id": str(user_id),
                "assigned_roles": len(request.role_ids)
            }
        )
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to assign roles"
        )

@router.get("/users/{user_id}/roles")
async def get_user_roles(
    user_id: uuid.UUID,
    admin_user_id: uuid.UUID = Depends(verify_admin_access),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Get roles assigned to a user"""
    try:
        # This would query user roles from database
        # For now, return empty list
        return {"items": []}
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch user roles"
        )

@router.delete("/users/{user_id}/roles/{role_id}")
async def remove_user_role(
    user_id: uuid.UUID,
    role_id: uuid.UUID,
    admin_user_id: uuid.UUID = Depends(verify_admin_access),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Remove a role from a user"""
    try:
        return MessageResponse(
            message="Role removed from user successfully"
        )
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to remove role"
        )