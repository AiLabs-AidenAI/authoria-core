# Authentication Service

A production-ready FastAPI authentication service with multi-provider support, admin approval workflow, and comprehensive security features.

## ⚡ Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Start the service  
python start_service.py
```

**Default Admin Login:**
- Email: `admin@example.com`
- Password: `admin123`

## 🔧 Configuration

### Environment Variables (.env)
```env
# Database
DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/auth_db

# Email (Optional - will fallback to console logging)
SMTP_HOST=smtp.gmail.com
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
FROM_EMAIL=noreply@yourapp.com

# OAuth Providers (Optional)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-secret
AZURE_CLIENT_ID=your-azure-client-id
AZURE_CLIENT_SECRET=your-azure-secret
AZURE_TENANT_ID=your-tenant-id

# Security
SECRET_KEY=your-super-secret-jwt-key-change-in-production
```

## 🌟 Features

- **Multi-Provider Auth**: Google OAuth, Azure/Microsoft SSO, Email OTP
- **Admin Approval**: Configurable approval workflow for new users  
- **Security**: Rate limiting, JWT tokens, password policies
- **Production Ready**: Docker support, comprehensive logging
- **API Documentation**: Interactive docs at `/docs`

## 📚 Integration Examples

### Frontend Integration (React/JavaScript)
```javascript
// Login with email/password
const loginResponse = await fetch('http://localhost:8000/v1/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: 'user@example.com', password: 'password123' })
});

// Request OTP
await fetch('http://localhost:8000/v1/auth/otp/request', {
  method: 'POST', 
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email: 'user@example.com' })
});

// Start OAuth flow
window.location.href = 'http://localhost:8000/v1/auth/oauth/google/start';
```

### Backend Integration (Node.js/Express)
```javascript
// Verify JWT token
const response = await fetch('http://localhost:8000/v1/auth/introspect', {
  headers: { 'Authorization': `Bearer ${token}` }
});
const result = await response.json();
if (result.active) {
  // Token is valid, proceed with request
}
```

### Backend Integration (Python/FastAPI)
```python
import httpx

async def verify_token(token: str):
    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:8000/v1/auth/introspect",
            headers={"Authorization": f"Bearer {token}"}
        )
        return response.json()
```

## 🔧 Administration

Access admin panel after authentication to:
- Approve/reject user signups
- Configure OAuth providers
- Manage user accounts and permissions
- View audit logs

## 🐳 Docker Deployment

```bash
# Start with Docker Compose
docker-compose up -d

# Or build and run manually
docker build -t auth-service .
docker run -p 8000:8000 auth-service
```

## 📖 API Documentation

Visit `http://localhost:8000/docs` for complete interactive API documentation with examples and testing interface.