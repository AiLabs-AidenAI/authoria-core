"""
Authentication API routes
"""

from fastapi import APIRouter, HTTPException, Depends, Response, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Dict, Any
import uuid
from datetime import datetime, timedelta

from ...core.security import create_tokens, verify_token
from ...core.simple_rate_limiter import rate_limit
from ...services.auth_service import AuthService
from ...services.otp_service import OTPService
from ...services.email_service import EmailService
from ...models.schemas import (
    SignupRequest, 
    LoginRequest, 
    OTPRequest, 
    OTPVerifyRequest,
    TokenResponse,
    MessageResponse
)

router = APIRouter()

# Dependency injection
def get_auth_service() -> AuthService:
    return AuthService()

def get_otp_service() -> 'SimpleOTPService':
    from ...services.simple_otp_service import SimpleOTPService
    return SimpleOTPService()

def get_email_service() -> 'SimpleEmailService':
    from ...services.simple_email_service import SimpleEmailService
    return SimpleEmailService()

# Settings for cookie flags
from ...core.config import get_settings
_settings = get_settings()


@router.post("/signup", response_model=MessageResponse)
async def signup(
    request: SignupRequest,
    req: Request,
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Create a new user signup request
    Requires admin approval before account is activated
    """
    # Rate limiting
    await rate_limit("signup", req.client.host, limit=3, window=60)
    
    try:
        result = await auth_service.create_signup_request(
            email=request.email,
            password=request.password,
            display_name=request.display_name,
            tenant_id=request.tenant_id,
            requested_app_id=request.requested_app_id,
            provider="local_password",
            ip_address=req.client.host
        )
        
        return MessageResponse(
            message="Signup request submitted. Awaiting admin approval.",
            data={"signup_id": str(result.id)}
        )
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post("/login", response_model=TokenResponse)
async def login(
    request: LoginRequest,
    response: Response,
    req: Request,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Authenticate user with email and password"""
    # Rate limiting
    await rate_limit("login", req.client.host, limit=5, window=60)
    
    try:
        result = await auth_service.authenticate_user(
            email=request.email,
            password=request.password,
            ip_address=req.client.host,
            user_agent=req.headers.get("user-agent")
        )
        
        if not result.success:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=result.error_message
            )
        
        # Set refresh token as httpOnly cookie
        response.set_cookie(
            key="refresh_token",
            value=result.refresh_token,
            max_age=30 * 24 * 60 * 60,  # 30 days
            httponly=True,
            secure=not _settings.DEBUG,  # allow non-HTTPS in development
            samesite="lax" if _settings.DEBUG else "strict"
        )
        
        return TokenResponse(
            access_token=result.access_token,
            token_type="bearer",
            expires_in=15 * 60,  # 15 minutes
            user_id=str(result.user_id),
            email=result.email
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication failed"
        )


@router.post("/otp/request", response_model=MessageResponse)
async def request_otp(
    request: OTPRequest,
    req: Request,
    otp_service = Depends(get_otp_service),
    email_service = Depends(get_email_service)
):
    """Request OTP for email-based authentication"""
    # Rate limiting
    await rate_limit("otp_request", req.client.host, limit=3, window=60)
    
    try:
        # Generate and store OTP
        otp_code = await otp_service.generate_otp(request.email)
        
        # Send OTP via email
        await email_service.send_otp_email(request.email, otp_code)
        
        return MessageResponse(
            message=f"OTP sent to {request.email}. Please check your email."
        )
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to send OTP"
        )


@router.post("/otp/verify", response_model=TokenResponse)
async def verify_otp(
    request: OTPVerifyRequest,
    response: Response,
    req: Request,
    otp_service = Depends(get_otp_service),
    auth_service: AuthService = Depends(get_auth_service)
):
    """Verify OTP and authenticate user"""
    try:
        # Verify OTP
        is_valid = await otp_service.verify_otp(request.email, request.otp)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired OTP"
            )
        
        # Check if user exists and is approved
        result = await auth_service.authenticate_with_otp(
            email=request.email,
            ip_address=req.client.host,
            user_agent=req.headers.get("user-agent")
        )
        
        if not result.success:
            # If user doesn't exist, create pending signup
            if "not found" in result.error_message.lower():
                await auth_service.create_signup_request(
                    email=request.email,
                    provider="email_otp",
                    ip_address=req.client.host
                )
                raise HTTPException(
                    status_code=status.HTTP_202_ACCEPTED,
                    detail="OTP verified. Account pending admin approval."
                )
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=result.error_message
            )
        
        # Set refresh token cookie
        response.set_cookie(
            key="refresh_token",
            value=result.refresh_token,
            max_age=30 * 24 * 60 * 60,
            httponly=True,
            secure=not _settings.DEBUG,  # allow non-HTTPS in development
            samesite="lax" if _settings.DEBUG else "strict"
        )
        
        return TokenResponse(
            access_token=result.access_token,
            token_type="bearer",
            expires_in=15 * 60,
            user_id=str(result.user_id),
            email=result.email
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OTP verification failed"
        )


@router.get("/oauth/{provider}/start")
async def start_oauth(
    provider: str,
    request: Request,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Start OAuth flow for supported providers (google, azure)"""
    try:
        result = await auth_service.start_oauth_flow(
            provider=provider,
            redirect_uri=str(request.url_for("oauth_callback", provider=provider)),
            state=request.query_params.get("state")
        )
        
        if not result.success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result.error_message
            )
        
        return RedirectResponse(result.redirect_url)
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start {provider} OAuth flow"
        )


@router.get("/oauth/{provider}/callback")
async def oauth_callback(
    provider: str,
    request: Request,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Handle OAuth callback from providers"""
    try:
        code = request.query_params.get("code")
        state = request.query_params.get("state")
        error = request.query_params.get("error")
        
        if error:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"OAuth error: {error}"
            )
        
        if not code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Authorization code not provided"
            )
        
        result = await auth_service.complete_oauth_flow(
            provider=provider,
            code=code,
            redirect_uri=str(request.url_for("oauth_callback", provider=provider)),
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
        
        if not result.success:
            if "pending approval" in result.error_message.lower():
                # Redirect to pending approval page
                return RedirectResponse(
                    url="/auth/pending-approval",
                    status_code=status.HTTP_302_FOUND
                )
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=result.error_message
            )
        
        # Set refresh token cookie
        response.set_cookie(
            key="refresh_token",
            value=result.refresh_token,
            max_age=30 * 24 * 60 * 60,
            httponly=True,
            secure=True,
            samesite="strict"
        )
        
        # Redirect to frontend with access token
        frontend_url = f"/auth/callback?token={result.access_token}&user_id={result.user_id}"
        return RedirectResponse(url=frontend_url)
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"{provider} OAuth callback failed"
        )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: Request,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Refresh access token using refresh token"""
    try:
        # Get refresh token from cookie or request body
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            # Fallback to request body
            body = await request.json()
            refresh_token = body.get("refresh_token")
        
        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not provided"
            )
        
        result = await auth_service.refresh_access_token(refresh_token)
        
        if not result.success:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=result.error_message
            )
        
        # Set new refresh token cookie
        response.set_cookie(
            key="refresh_token",
            value=result.new_refresh_token,
            max_age=30 * 24 * 60 * 60,
            httponly=True,
            secure=not _settings.DEBUG,  # allow non-HTTPS in development
            samesite="lax" if _settings.DEBUG else "strict"
        )
        
        return TokenResponse(
            access_token=result.access_token,
            token_type="bearer",
            expires_in=15 * 60,
            user_id=str(result.user_id),
            email=result.email
        )
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token refresh failed"
        )


@router.post("/logout", response_model=MessageResponse)
async def logout(
    request: Request,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Logout user and revoke refresh token"""
    try:
        refresh_token = request.cookies.get("refresh_token")
        if refresh_token:
            await auth_service.revoke_refresh_token(refresh_token)
        
        # Clear refresh token cookie
        response.delete_cookie("refresh_token")
        
        return MessageResponse(message="Successfully logged out")
    
    except Exception as e:
        # Always return success for logout
        response.delete_cookie("refresh_token")
        return MessageResponse(message="Successfully logged out")


@router.post("/introspect")
async def introspect_token(
    request: Request,
    auth_service: AuthService = Depends(get_auth_service)
):
    """Token introspection endpoint for services and gateways"""
    try:
        # Get token from Authorization header
        auth_header = request.headers.get("authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authorization header"
            )
        
        token = auth_header.split(" ")[1]
        payload = verify_token(token)
        
        return {
            "active": True,
            "user_id": payload.get("sub"),
            "email": payload.get("email"),
            "exp": payload.get("exp"),
            "iat": payload.get("iat"),
            "scope": payload.get("scope", "")
        }
    
    except Exception:
        return {"active": False}