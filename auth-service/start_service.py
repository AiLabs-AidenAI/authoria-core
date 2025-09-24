#!/usr/bin/env python3
"""
FastAPI Authentication Service - Production Ready
Start with: python start_service.py

Features:
- Multi-provider OAuth (Google, Azure/Microsoft)
- Email OTP authentication
- Admin approval workflow
- Rate limiting and security controls
- Complete API documentation

Setup Instructions:
1. Install dependencies: pip install -r requirements.txt
2. Configure environment variables (see .env.example)
3. Start database: docker-compose up -d db redis
4. Run service: python start_service.py

Default Admin Credentials:
- Email: admin@example.com
- Password: admin123

Integration Examples:
See /docs for complete API documentation and code examples.

"""

import uvicorn
from main import app
from app.core.config import get_settings

if __name__ == "__main__":
    settings = get_settings()
    
    print("🚀 Starting Authentication Service...")
    print("📖 API Documentation: http://localhost:8000/docs")
    print("🔧 Admin Login: admin@example.com / admin123")
    print("⚡ Frontend Integration: See /docs")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        access_log=True
    )