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
from app.api.v1.routes import auth, admin, users, admin_config, tenants
from app.core.security import verify_token
from app.models.user import User

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

security = HTTPBearer(auto_error=False)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await setup_database()
    await init_db()
    logger.info("Database initialized")
    yield
    # Shutdown
    logger.info("Shutting down auth service")

async def setup_database():
    """Complete database setup including creation and initial data"""
    from app.core.database import Base, AsyncSessionLocal
    from app.models.user import User
    from app.core.security import hash_password
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy import create_engine, text
    
    settings = get_settings()
    
    # 1. Create database if it doesn't exist (PostgreSQL)
    try:
        sync_url = settings.DATABASE_URL.replace("asyncpg", "psycopg2")
        engine = create_engine(sync_url.replace("/auth_db", "/postgres"))
        
        with engine.connect() as conn:
            conn.execute(text("COMMIT"))  # End any existing transaction
            result = conn.execute(text("SELECT 1 FROM pg_database WHERE datname = 'auth_db'"))
            if not result.fetchone():
                conn.execute(text("CREATE DATABASE auth_db"))
                logger.info("Database 'auth_db' created")
            else:
                logger.info("Database 'auth_db' already exists")
        
        engine.dispose()
    except Exception as e:
        logger.info(f"Database creation info: {e} (continuing anyway)")
    
    # 2. Create tables
    try:
        engine = create_async_engine(settings.DATABASE_URL)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await engine.dispose()
        logger.info("Database tables ready")
    except Exception as e:
        logger.error(f"Table creation error: {e}")
        raise
    
    # 3. Create admin user if doesn't exist
    try:
        async with AsyncSessionLocal() as db:
            from sqlalchemy import select
            
            result = await db.execute(
                select(User).where(User.email == "admin@example.com")
            )
            
            if not result.scalar_one_or_none():
                admin_user = User(
                    email="admin@example.com",
                    display_name="System Administrator", 
                    password_hash=hash_password("admin123"),
                    is_admin=True,
                    is_approved=True,
                    is_active=True,
                    email_verified=True,
                    role="admin"
                )
                
                db.add(admin_user)
                await db.commit()
                logger.info("Admin user created: admin@example.com / admin123")
            else:
                logger.info("Admin user already exists")
                
    except Exception as e:
        logger.error(f"Admin user setup error: {e}")
        raise

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
app.include_router(tenants.router, prefix="/v1", tags=["tenants"])

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