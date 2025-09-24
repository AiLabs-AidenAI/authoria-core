#!/usr/bin/env python3
"""
Authentication Service Startup Script
Run this to start the authentication service with all required configurations
"""

import os
import sys
import subprocess
import asyncio
from pathlib import Path

def check_requirements():
    """Check if all requirements are installed"""
    try:
        import fastapi
        import sqlalchemy
        import passlib
        import httpx
        import redis
        print("✓ All required packages are installed")
        return True
    except ImportError as e:
        print(f"✗ Missing required package: {e}")
        print("Please run: pip install -r requirements.txt")
        return False

def check_database():
    """Check if PostgreSQL is available"""
    try:
        import psycopg2
        print("✓ PostgreSQL driver available")
        return True
    except ImportError:
        print("✗ PostgreSQL driver not found")
        print("Please install: pip install psycopg2-binary")
        return False

def setup_environment():
    """Set up environment variables with defaults"""
    env_vars = {
        "DEBUG": "true",
        "DATABASE_URL": "postgresql+asyncpg://auth_user:auth_password@localhost:5432/auth_db",
        "SECRET_KEY": "dev-secret-key-change-in-production",
        "ALLOWED_ORIGINS": "http://localhost:3000,http://localhost:5173,http://localhost:8080",
        "SMTP_HOST": "smtp.gmail.com",
        "SMTP_PORT": "587",
        "FROM_EMAIL": "noreply@yourapp.com"
    }
    
    for key, default_value in env_vars.items():
        if not os.getenv(key):
            os.environ[key] = default_value
            print(f"✓ Set {key} to default value")

def print_admin_credentials():
    """Print admin credentials for initial login"""
    print("\n" + "="*50)
    print("🔑 ADMIN CREDENTIALS (for initial setup)")
    print("="*50)
    print("Email: admin@example.com")
    print("Password: admin123")
    print("="*50)
    print("⚠️  Please change these credentials after first login!")
    print("="*50)

def print_api_endpoints():
    """Print available API endpoints"""
    print("\n" + "="*50)
    print("🔗 API ENDPOINTS")
    print("="*50)
    print("Base URL: http://localhost:8000")
    print("")
    print("Authentication:")
    print("  POST /v1/auth/login - Email/password login")
    print("  POST /v1/auth/signup - Create signup request")
    print("  POST /v1/auth/otp/request - Request OTP")
    print("  POST /v1/auth/otp/verify - Verify OTP")
    print("  GET  /v1/auth/oauth/google/start - Start Google OAuth")
    print("  GET  /v1/auth/oauth/azure/start - Start Azure OAuth")
    print("")
    print("Admin:")
    print("  GET  /v1/admin/pending-signups - List pending signups")
    print("  POST /v1/admin/approve-signup/{id} - Approve signup")
    print("  GET  /v1/admin/users - List all users")
    print("")
    print("Documentation:")
    print("  GET  /docs - Swagger API documentation")
    print("  GET  /redoc - ReDoc API documentation")
    print("="*50)

def main():
    """Main startup function"""
    print("🚀 Starting Authentication Service...")
    print("="*50)
    
    # Check requirements
    if not check_requirements():
        sys.exit(1)
        
    if not check_database():
        print("⚠️  PostgreSQL driver not found, but continuing...")
    
    # Setup environment
    setup_environment()
    
    # Print credentials and endpoints
    print_admin_credentials()
    print_api_endpoints()
    
    print("\n🎯 Starting server on http://localhost:8000")
    print("Press Ctrl+C to stop the server\n")
    
    try:
        # Start the FastAPI server
        import uvicorn
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=8000,
            reload=True,
            access_log=True,
            log_level="info"
        )
    except KeyboardInterrupt:
        print("\n👋 Authentication service stopped")
    except Exception as e:
        print(f"\n❌ Error starting service: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()