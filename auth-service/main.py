"""
FastAPI Authentication Service
Secure authentication with multiple providers and admin approval workflow
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import RedirectResponse
import uvicorn
import logging
from typing import Optional

from app.core.config import get_settings
from app.core.database import init_db
from app.api.v1.routes import auth, admin, users, admin_config
from app.core.security import verify_token
from app.models.user import User

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

security = HTTPBearer(auto_error=False)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_db()
    logger.info("Database initialized")
    yield
    # Shutdown
    logger.info("Shutting down auth service")

app = FastAPI(
    title="Authentication Service",
    description="Secure multi-provider authentication with admin approval workflow",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(auth.router, prefix="/v1/auth", tags=["authentication"])
app.include_router(admin.router, prefix="/v1/admin", tags=["admin"])
app.include_router(users.router, prefix="/v1/users", tags=["users"])
app.include_router(admin_config.router, prefix="/v1", tags=["admin-config"])

@app.get("/")
async def root():
    return {"message": "Authentication Service v1.0.0", "status": "healthy"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "auth"}

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[User]:
    """Get current authenticated user from JWT token"""
    if not credentials:
        return None
    
    try:
        payload = verify_token(credentials.credentials)
        user_id = payload.get("sub")
        if not user_id:
            return None
        
        # In real implementation, fetch user from database
        # user = await User.get(user_id)
        # return user
        return None
    except Exception:
        return None

if __name__ == "__main__":
    settings = get_settings()
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        access_log=True
    )