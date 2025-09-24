# Authentication Service

A comprehensive FastAPI-based authentication service with multiple provider support.

## Features

- 🔐 Local password authentication
- 📧 Email OTP authentication  
- 🔑 OAuth2 with Google and Azure
- 👥 Admin approval workflow
- 📊 Admin dashboard with user management
- 🔒 JWT token-based authentication
- 📝 Comprehensive audit logging
- ⚡ Rate limiting and security features

## Quick Start

1. **Setup the service:**
   ```bash
   cd auth-service
   python run_setup.py
   ```

2. **Start the service:**
   ```bash
   python start.py
   ```

3. **Access the service:**
   - API: http://localhost:8000
   - Docs: http://localhost:8000/docs
   - Admin login: admin@example.com / admin123

## Project Structure

```
auth-service/
├── app/
│   ├── api/v1/routes/          # API endpoints
│   ├── core/                   # Core utilities
│   ├── models/                 # Database models
│   ├── providers/              # Auth providers
│   └── services/               # Business logic
├── main.py                     # FastAPI app
├── setup_complete.py           # Database setup
├── run_setup.py               # Setup runner
└── start.py                   # Quick start
```

## Configuration

The service uses SQLite by default for development. For production, configure:
- Database URL
- OAuth provider credentials
- SMTP settings (optional, console logging used in development)
- Redis (optional, in-memory used in development)

## API Endpoints

### Authentication
- `POST /v1/auth/signup` - Create signup request
- `POST /v1/auth/login` - Login with email/password
- `POST /v1/auth/otp/request` - Request OTP
- `POST /v1/auth/otp/verify` - Verify OTP
- `POST /v1/auth/refresh` - Refresh token
- `POST /v1/auth/logout` - Logout

### OAuth
- `GET /v1/auth/oauth/{provider}/start` - Start OAuth flow
- `GET /v1/auth/oauth/{provider}/callback` - OAuth callback

### Admin
- `GET /v1/admin/pending-signups` - List pending signups
- `POST /v1/admin/pending-signups/{id}/approve` - Approve signup
- `GET /v1/admin/users` - List users
- `GET /v1/admin/config/*` - Configuration management

## Development

The service includes development-friendly features:
- Console-based email notifications (no SMTP required)
- In-memory OTP storage (no Redis required)
- SQLite database (no external DB required)
- Auto-reload on code changes