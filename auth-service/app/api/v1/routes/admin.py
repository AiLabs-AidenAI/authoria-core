"""
Admin API routes for user management and system administration
"""

from fastapi import APIRouter, HTTPException, Depends, Request, status, Query
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any
import uuid
from datetime import datetime

from ...services.auth_service import AuthService
from ...core.security import verify_token
from ...models.schemas import MessageResponse, PaginatedResponse

router = APIRouter()

# Request/Response models
class ApproveSignupRequest(BaseModel):
    default_role_id: Optional[str] = None
    notify_user: bool = True

class BulkApproveRequest(BaseModel):
    ids: List[uuid.UUID]
    default_role_id: Optional[str] = None
    notify_users: bool = True

class CreateUserRequest(BaseModel):
    email: EmailStr
    display_name: str
    password: Optional[str] = None
    tenant_id: Optional[uuid.UUID] = None
    is_admin: bool = False

class RejectSignupRequest(BaseModel):
    reason: str = Field(..., min_length=1, max_length=500)

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
        
        # In a real implementation, verify the user is admin
        # For now, we'll assume any authenticated user can access admin functions
        return uuid.UUID(user_id)
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token verification failed"
        )

def get_auth_service() -> AuthService:
    return AuthService()


@router.get("/pending-signups")
async def get_pending_signups(
    status: str = Query("pending", regex="^(pending|approved|rejected|all)$"),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    admin_user_id: uuid.UUID = Depends(verify_admin_access),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Get paginated list of pending signup requests"""
    try:
        result = await auth_service.get_pending_signups(
            status=status,
            page=page,
            limit=limit
        )
        
        return PaginatedResponse(
            items=result["signups"],
            total=result["total"],
            page=result["page"],
            limit=result["limit"],
            total_pages=result["total_pages"]
        )
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch pending signups"
        )


@router.post("/pending-signups/{signup_id}/approve")
async def approve_signup(
    signup_id: uuid.UUID,
    request: ApproveSignupRequest,
    admin_user_id: uuid.UUID = Depends(verify_admin_access),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Approve a single signup request"""
    try:
        user = await auth_service.approve_signup(
            pending_id=signup_id,
            admin_user_id=admin_user_id,
            default_role_id=request.default_role_id
        )
        
        return MessageResponse(
            message=f"User {user.email} approved successfully",
            data={"user_id": str(user.id), "email": user.email}
        )
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to approve signup"
        )


@router.post("/pending-signups/bulk-approve")
async def bulk_approve_signups(
    request: BulkApproveRequest,
    admin_user_id: uuid.UUID = Depends(verify_admin_access),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Approve multiple signup requests"""
    approved_users = []
    failed_approvals = []
    
    for signup_id in request.ids:
        try:
            user = await auth_service.approve_signup(
                pending_id=signup_id,
                admin_user_id=admin_user_id,
                default_role_id=request.default_role_id
            )
            approved_users.append({
                "id": str(user.id),
                "email": user.email
            })
        except Exception as e:
            failed_approvals.append({
                "id": str(signup_id),
                "error": str(e)
            })
    
    return MessageResponse(
        message=f"Approved {len(approved_users)} users, {len(failed_approvals)} failed",
        data={
            "approved": approved_users,
            "failed": failed_approvals
        }
    )


@router.post("/pending-signups/{signup_id}/reject")
async def reject_signup(
    signup_id: uuid.UUID,
    request: RejectSignupRequest,
    admin_user_id: uuid.UUID = Depends(verify_admin_access),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Reject a signup request"""
    try:
        await auth_service.reject_signup(
            pending_id=signup_id,
            admin_user_id=admin_user_id,
            reason=request.reason
        )
        
        return MessageResponse(
            message="Signup request rejected",
            data={"signup_id": str(signup_id)}
        )
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reject signup"
        )


@router.get("/users")
async def get_users(
    tenant_id: Optional[uuid.UUID] = None,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    search: Optional[str] = None,
    admin_user_id: uuid.UUID = Depends(verify_admin_access),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Get paginated list of users with their login modes"""
    try:
        result = await auth_service.get_users(
            tenant_id=tenant_id,
            page=page,
            limit=limit,
            search=search
        )
        
        return PaginatedResponse(
            items=result["users"],
            total=result["total"],
            page=result["page"],
            limit=result["limit"],
            total_pages=result["total_pages"]
        )
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch users"
        )


@router.post("/users", response_model=MessageResponse)
async def create_user_manually(
    request: CreateUserRequest,
    admin_user_id: uuid.UUID = Depends(verify_admin_access),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Create a user manually without approval process"""
    try:
        user = await auth_service.create_user_manually(
            email=request.email,
            display_name=request.display_name,
            password=request.password,
            tenant_id=request.tenant_id,
            is_admin=request.is_admin,
            admin_user_id=admin_user_id
        )
        
        return MessageResponse(
            message=f"User {user.email} created successfully",
            data={
                "user_id": str(user.id),
                "email": user.email,
                "display_name": user.display_name
            }
        )
    
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


@router.get("/users/{user_id}")
async def get_user_details(
    user_id: uuid.UUID,
    admin_user_id: uuid.UUID = Depends(verify_admin_access),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Get detailed information about a specific user"""
    try:
        user_details = await auth_service.get_user_details(user_id)
        return user_details
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch user details"
        )


@router.patch("/users/{user_id}/status")
async def update_user_status(
    user_id: uuid.UUID,
    is_active: bool,
    admin_user_id: uuid.UUID = Depends(verify_admin_access),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Enable or disable a user account"""
    try:
        await auth_service.update_user_status(
            user_id=user_id,
            is_active=is_active,
            admin_user_id=admin_user_id
        )
        
        status_text = "enabled" if is_active else "disabled"
        return MessageResponse(
            message=f"User account {status_text} successfully"
        )
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update user status"
        )


@router.get("/audit-logs")
async def get_audit_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    action_type: Optional[str] = None,
    target_type: Optional[str] = None,
    admin_user_id: uuid.UUID = Depends(verify_admin_access),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Get system audit logs"""
    try:
        result = await auth_service.get_audit_logs(
            page=page,
            limit=limit,
            action_type=action_type,
            target_type=target_type
        )
        
        return PaginatedResponse(
            items=result["logs"],
            total=result["total"],
            page=result["page"],
            limit=result["limit"],
            total_pages=result["total_pages"]
        )
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch audit logs"
        )


@router.get("/stats")
async def get_admin_stats(
    admin_user_id: uuid.UUID = Depends(verify_admin_access),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Get system statistics for admin dashboard"""
    try:
        stats = await auth_service.get_admin_stats()
        return stats
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch system statistics"
        )