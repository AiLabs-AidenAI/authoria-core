# Authentication Service

A centralized authentication service that provides SSO, OAuth, and user management capabilities for multiple applications.

## Features

- **Multi-Provider Authentication**: Support for local passwords, email OTP, Google OAuth, Azure AD, SAML, and more
- **Admin Dashboard**: Configure authentication providers, manage users, and approve registrations  
- **Centralized Control**: Single service to control authentication for all your applications
- **Security Features**: Rate limiting, audit logging, encryption, and role-based access
- **Scalable Architecture**: Built with FastAPI, PostgreSQL, Redis, and Docker

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   React Admin   │    │   FastAPI       │    │   PostgreSQL    │
│   Dashboard     │───▶│   Backend       │───▶│   Database      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   Redis Cache   │
                       │   & Sessions    │
                       └─────────────────┘
```

## Quick Start

### Frontend (React Dashboard)

The frontend is already running in Lovable. You can:
- Visit `/admin/auth-config` to configure authentication providers
- Visit `/admin/pending-requests` to manage user approvals

### Backend (FastAPI Service)

1. **Prerequisites**
   ```bash
   # Install Docker and Docker Compose
   docker --version
   docker-compose --version
   ```

2. **Environment Setup**
   ```bash
   cd auth-service
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Start Services**
   ```bash
   # Start all services (API, PostgreSQL, Redis)
   docker-compose up -d

   # View logs
   docker-compose logs -f auth-api

   # Stop services
   docker-compose down
   ```

4. **Database Migration**
   ```bash
   # Run initial migration
   docker-compose exec auth-api alembic upgrade head
   ```

### Environment Variables

Create `.env` file in the `auth-service` directory:

```env
# Database
DATABASE_URL=postgresql://auth_user:auth_password@db:5432/auth_db

# Redis
REDIS_URL=redis://redis:6379/0

# Security
SECRET_KEY=your-super-secret-key-here
ENCRYPTION_KEY=your-32-byte-encryption-key-here

# SMTP (for email verification)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# OAuth Providers
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Application Settings
ALLOWED_ORIGINS=https://your-admin-dashboard.com,http://localhost:3000
TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=30
```

## API Endpoints

### Authentication
- `POST /v1/auth/signup` - User registration
- `POST /v1/auth/login` - Password login
- `POST /v1/auth/otp/request` - Request OTP
- `POST /v1/auth/otp/verify` - Verify OTP
- `POST /v1/auth/refresh` - Refresh token
- `GET /v1/auth/oauth/{provider}/start` - Start OAuth flow

### Admin Management  
- `GET /v1/admin/pending-signups` - List pending registrations
- `POST /v1/admin/pending-signups/{id}/approve` - Approve registration
- `GET /v1/admin/users` - List users
- `PUT /v1/admin/users/{id}` - Update user
- `GET /v1/admin/providers` - List auth providers
- `POST /v1/admin/providers/{id}/config` - Update provider config

## Integration Guide

To integrate this auth service with your applications:

### 1. Frontend Integration

```javascript
// Configure your app to use this auth service
const authConfig = {
  authServiceUrl: 'http://localhost:8000',
  clientId: 'your-client-id',
  redirectUri: 'https://yourapp.com/auth/callback'
};

// Login redirect
window.location.href = `${authConfig.authServiceUrl}/v1/auth/oauth/start?client_id=${authConfig.clientId}&redirect_uri=${authConfig.redirectUri}`;

// Token validation
const validateToken = async (token) => {
  const response = await fetch(`${authConfig.authServiceUrl}/v1/auth/introspect`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  return response.json();
};
```

### 2. Backend Integration

```python
# Validate tokens from your backend
import requests

def validate_auth_token(token: str) -> dict:
    response = requests.post(
        "http://localhost:8000/v1/auth/introspect",
        headers={"Authorization": f"Bearer {token}"}
    )
    return response.json()
```

## Provider Configuration

### Google OAuth Setup
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable Google+ API
4. Create OAuth 2.0 credentials
5. Add authorized redirect URIs: `http://localhost:8000/v1/auth/oauth/google/callback`

### SAML Setup
1. Configure your SAML IdP
2. Set Entity ID: `http://localhost:8000/v1/auth/saml/metadata`
3. Set ACS URL: `http://localhost:8000/v1/auth/saml/acs`

## Security Features

- **Encryption**: All sensitive data encrypted at rest
- **Rate Limiting**: Configurable limits on login attempts
- **Audit Logging**: Complete audit trail of all actions
- **Token Security**: Short-lived access tokens with refresh rotation
- **CORS Protection**: Configurable allowed origins
- **SQL Injection Protection**: Parameterized queries
- **CSRF Protection**: Built-in CSRF tokens

## Development

### Running Locally

```bash
# Backend
cd auth-service
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows
pip install -r requirements.txt
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Frontend is running in Lovable
```

### Database Schema

The service uses the following main tables:
- `users` - User accounts and profiles
- `auth_providers` - Configured authentication providers
- `pending_signups` - Registration requests awaiting approval
- `user_tokens` - Active and refresh tokens
- `audit_logs` - Security and action audit trail

## Production Deployment

### Docker Production
1. Build production images
2. Configure load balancer
3. Set up SSL certificates
4. Configure monitoring and logging
5. Set up backup strategy

### Kubernetes
Helm charts and Kubernetes manifests are available in the `k8s/` directory.

## Support

For questions and support:
1. Check the API documentation at `http://localhost:8000/docs`
2. Review the audit logs for troubleshooting
3. Check Docker logs: `docker-compose logs`

## License

MIT License - see LICENSE file for details.

---

## Lovable Project Info

**URL**: https://lovable.dev/projects/8c41d3dc-c2a0-4a3d-8af4-907f06d7034b

### Frontend Technologies
- Vite
- TypeScript  
- React
- shadcn-ui
- Tailwind CSS

### How to Deploy
Simply open [Lovable](https://lovable.dev/projects/8c41d3dc-c2a0-4a3d-8af4-907f06d7034b) and click on Share → Publish.
