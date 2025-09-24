"""
Complete setup script to initialize the authentication service
"""

import asyncio
import os
import sys
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import create_engine, text

# Add the app directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.core.config import get_settings
from app.core.database import Base, AsyncSessionLocal
from app.models.user import User, AuthProviderLink, PendingSignup, RefreshToken, LoginAttempt, AuditLog

settings = get_settings()

async def create_database():
    """Create database if it doesn't exist"""
    try:
        # Create sync engine for database creation
        sync_url = settings.DATABASE_URL.replace("asyncpg", "psycopg2")
        engine = create_engine(sync_url.replace("/auth_db", "/postgres"))
        
        with engine.connect() as conn:
            # Check if database exists
            result = conn.execute(text("SELECT 1 FROM pg_database WHERE datname = 'auth_db'"))
            if not result.fetchone():
                conn.execute(text("COMMIT"))  # End transaction
                conn.execute(text("CREATE DATABASE auth_db"))
                print("Database 'auth_db' created successfully")
            else:
                print("Database 'auth_db' already exists")
        
        engine.dispose()
    except Exception as e:
        print(f"Database creation error: {e}")
        # If database creation fails, continue anyway

async def create_tables():
    """Create all database tables"""
    try:
        engine = create_async_engine(settings.DATABASE_URL)
        
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        await engine.dispose()
        print("Database tables created successfully")
    except Exception as e:
        print(f"Table creation error: {e}")
        raise

async def create_admin_user():
    """Create initial admin user"""
    from app.core.security import hash_password
    
    try:
        async with AsyncSessionLocal() as db:
            from sqlalchemy import select
            
            # Check if admin already exists
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
                    email_verified=True
                )
                
                db.add(admin_user)
                await db.commit()
                print("Admin user created: admin@example.com / admin123")
            else:
                print("Admin user already exists")
                
    except Exception as e:
        print(f"Admin user creation error: {e}")
        raise

async def main():
    """Main setup function"""
    print("Starting authentication service setup...")
    
    try:
        await create_database()
        await create_tables()
        await create_admin_user()
        
        print("\n✅ Setup completed successfully!")
        print("\nDefault admin credentials:")
        print("Email: admin@example.com")
        print("Password: admin123")
        print("\n🚀 You can now start the service with: python main.py")
        
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)