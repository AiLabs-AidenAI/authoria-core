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

1. **Install dependencies:**
   ```bash
   cd auth-service
   pip install -r requirements.txt
   ```

2. **Setup environment (optional):**
   ```bash
   cp .env.example .env
   # Edit .env with your database and other settings
   ```

3. **Start the service:**
   ```bash
   python main.py
   ```
   
   The service will automatically:
   - Create the PostgreSQL database if it doesn't exist
   - Set up all required tables
   - Create an admin user (admin@example.com / admin123)

4. **Access the service:**
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

The service uses PostgreSQL by default. Configure via environment variables or `.env` file:

- **DATABASE_URL**: PostgreSQL connection string (required)
- **OAuth provider credentials**: Google, Azure (optional)
- **SMTP settings**: Email configuration (optional, uses console logging if not provided)
- **Redis**: Caching and sessions (optional, uses in-memory if not provided)

### PostgreSQL Setup
Make sure PostgreSQL is running and accessible. The service will create the database automatically.

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