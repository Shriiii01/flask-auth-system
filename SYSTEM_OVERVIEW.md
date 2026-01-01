# 🔍 Complete System Overview

## What Is This System?

This is a **Flask-based Authentication & Authorization System** - a complete backend API for handling user authentication, authorization, and user management. It was built as a production-ready authentication solution.

**Built by**: Shri Jambhale (shrijambhale8@gmail.com)  
**Purpose**: Enterprise-ready authentication system with JWT, OAuth, Role-Based Access Control (RBAC)

---

## 🏗️ System Architecture

### High-Level Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Flask Application                      │
│  (REST API Server running on port 5001)                  │
└─────────────────────────────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
   ┌────────┐      ┌──────────┐      ┌─────────┐
   │Database│      │  Redis   │      │  SMTP   │
   │(SQLite │      │ (Rate    │      │ (Email  │
   │/Postgres│      │ Limiting)│      │ Sending)│
   └────────┘      └──────────┘      └─────────┘
```

---

## 📁 Project Structure Explained

```
flask-auth-system/
│
├── flask_auth/                    # Main application package
│   ├── __init__.py               # App factory - creates Flask app
│   ├── models.py                 # Database models (User, Role, etc.)
│   ├── extensions.py             # Flask extensions setup (DB, JWT, Redis)
│   ├── oauth.py                  # GitHub OAuth configuration
│   │
│   ├── routes/                   # API endpoints (URLs)
│   │   ├── auth.py              # Authentication routes (login, register)
│   │   ├── main.py              # General routes (home page)
│   │   └── admin_routes.py      # Admin routes (user management, roles)
│   │
│   └── utils/                    # Helper functions
│       ├── utils.py             # Decorators (role_required, admin_required)
│       └── logger.py            # Logging utilities
│
├── migrations/                    # Database migrations (Alembic)
│   └── versions/                # Migration history
│
├── tests/                        # Unit tests
│
├── config.py                     # Configuration settings
├── run.py                        # Application entry point
├── reset_db.py                   # Database reset script
├── setup_db.py                   # Database setup script
├── requirements.txt              # Python dependencies
├── Dockerfile                    # Docker image definition
├── docker-compose.yml           # Docker services (app + Redis)
└── README.md                    # Project documentation
```

---

## 🗄️ Database Structure

### Tables:

1. **`user`** - Stores user accounts
   - `id`, `username`, `email`, `password_hash`
   - `is_active`, `is_verified`, `email_verification_token`
   - `reset_token`, `token_expiration`, `token_revoked_at`
   - `failed_attempts`, `is_locked`, `lock_until` (security)
   - `totp_secret`, `is_totp_enabled` (2FA support)
   - `created_at`, `updated_at`

2. **`role`** - Stores roles (admin, editor, etc.)
   - `id`, `name`, `description`

3. **`user_roles`** - Many-to-many relationship table
   - Links users to roles

4. **`activity_log`** - Tracks user actions
   - `id`, `actor_id`, `action`, `target`, `timestamp`

5. **`token`** - Stores JWT tokens (for revocation)
   - `id`, `user_id`, `token`, `expiration`, `revoked_at`

### Where Data Is Stored:

- **Development**: SQLite database at `instance/app.db`
- **Production**: PostgreSQL (configured via `DATABASE_URL` environment variable)

---

## 🔐 Authentication Flow

### 1. User Registration
```
User → POST /auth/register
  ↓
System creates user account
  ↓
Generates email verification token
  ↓
Returns verification link (BUT EMAIL NOT SENT - MISSING!)
```

### 2. Email Verification
```
User clicks verification link
  ↓
GET /auth/verify-email/<token>
  ↓
System marks user as verified
```

### 3. User Login
```
User → POST /auth/login (email + password)
  ↓
System validates credentials
  ↓
Generates JWT access token + refresh token
  ↓
Returns tokens to user
```

### 4. Using Protected Routes
```
User → GET /admin/users (with JWT token in header)
  ↓
System validates JWT token
  ↓
Checks user roles/permissions
  ↓
Returns data if authorized
```

---

## 🛣️ API Endpoints

### Authentication Routes (`/auth`)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/auth/register` | Register new user | No |
| GET | `/auth/verify-email/<token>` | Verify email | No |
| POST | `/auth/login` | Login user | No |
| POST | `/auth/refresh` | Refresh access token | Refresh token |
| POST | `/auth/logout` | Logout (revoke token) | Yes |
| POST | `/auth/forgot-password` | Request password reset | No |
| POST | `/auth/reset-password` | Reset password | No |
| POST | `/auth/change-password` | Change password | Yes |
| GET | `/auth/github` | GitHub OAuth login | No |
| GET | `/auth/github/callback` | GitHub OAuth callback | No |

### Main Routes (`/`)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/` | Home page | Yes |

### Admin Routes (`/admin`)

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/admin/users` | List all users | Admin |
| PUT | `/admin/users/<id>` | Update user | Admin |
| DELETE | `/admin/users/<id>` | Delete user | Admin |
| POST | `/admin/roles` | Create role | Admin |
| GET | `/admin/roles` | List roles | Admin |
| DELETE | `/admin/roles/<id>` | Delete role | Admin |
| POST | `/admin/users/<id>/roles` | Assign role to user | Admin |
| DELETE | `/admin/users/<id>/roles` | Remove role from user | Admin |
| GET | `/admin/activity-logs` | Get activity logs | Admin |

---

## 🔧 Key Components Explained

### 1. **Flask Application** (`flask_auth/__init__.py`)
- Creates the Flask app
- Registers blueprints (routes)
- Sets up Swagger documentation
- Configures CORS, JWT, database

### 2. **Database Models** (`flask_auth/models.py`)
- `User`: User accounts with all fields
- `Role`: Roles (admin, editor, etc.)
- `ActivityLog`: Audit trail
- `Token`: JWT token management

### 3. **Authentication Routes** (`flask_auth/routes/auth.py`)
- Handles registration, login, logout
- JWT token generation
- Password reset flow
- GitHub OAuth integration

### 4. **Admin Routes** (`flask_auth/routes/admin_routes.py`)
- User management (CRUD)
- Role management
- Activity log viewing

### 5. **Utilities** (`flask_auth/utils/utils.py`)
- `@role_required("admin")` - Decorator to protect routes
- `@admin_required` - Decorator for admin-only routes

### 6. **Extensions** (`flask_auth/extensions.py`)
- Database (SQLAlchemy)
- JWT Manager
- Rate Limiter (Redis)
- CORS
- Bcrypt (password hashing)

---

## 🔒 Security Features

1. **Password Hashing**: Bcrypt (one-way encryption)
2. **JWT Tokens**: Secure token-based authentication
3. **Token Revocation**: Can revoke tokens (logout)
4. **Rate Limiting**: Prevents brute-force attacks (Redis)
5. **Email Verification**: Users must verify email
6. **Account Locking**: Locks account after failed attempts
7. **Role-Based Access Control**: Different permissions per role
8. **CORS**: Cross-origin resource sharing configured

---

## 📧 Email System Status

### ⚠️ **CURRENTLY NOT WORKING**

- Email configuration exists in `config.py`
- SMTP settings are configured
- **BUT**: Email sending code is NOT implemented
- Verification links are generated but NOT sent via email
- Users must manually copy/paste verification links

### What's Missing:
- No Flask-Mail integration
- No email sending function
- No email templates

---

## 🚀 How to Run

### Option 1: Docker (Recommended)
```bash
docker-compose up --build
```
- Runs Flask app + Redis
- Access at `http://localhost:5001`
- Swagger docs at `http://localhost:5001/docs`

### Option 2: Local Development
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python run.py
```

---

## 🔍 Data Flow Example

### User Registration Flow:
```
1. Client sends: POST /auth/register
   {
     "username": "john",
     "email": "john@example.com",
     "password": "secret123"
   }

2. Flask receives request
   ↓
3. Checks if email/username exists
   ↓
4. Creates User object in database
   ↓
5. Generates email verification token
   ↓
6. Returns verification link (but doesn't send email!)
   ↓
7. Client receives:
   {
     "message": "User registered successfully",
     "verification_link": "http://localhost:5001/auth/verify-email/abc123..."
   }
```

### User Login Flow:
```
1. Client sends: POST /auth/login
   {
     "email": "john@example.com",
     "password": "secret123"
   }

2. Flask validates credentials
   ↓
3. Checks if user is verified
   ↓
4. Generates JWT access token (expires in 1 hour)
   ↓
5. Generates JWT refresh token (expires in 30 days)
   ↓
6. Returns tokens
   ↓
7. Client receives:
   {
     "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
     "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
     "user": {...}
   }
```

---

## 🎯 What This System Does Well

✅ Complete authentication system  
✅ JWT token management  
✅ Role-based access control  
✅ GitHub OAuth integration  
✅ Rate limiting  
✅ Database migrations  
✅ Swagger API documentation  
✅ Docker support  
✅ Security best practices  

---

## ⚠️ What's Missing/Broken

❌ **Email sending** - Configured but not implemented  
❌ **Email verification emails** - Links generated but not sent  
❌ **Password reset emails** - Not sending emails  
❌ **Production database** - Defaults to SQLite (not production-ready)  

---

## 📊 Technology Stack

- **Framework**: Flask 3.1.0
- **Database**: SQLAlchemy (SQLite/PostgreSQL)
- **Authentication**: Flask-JWT-Extended
- **OAuth**: Authlib (GitHub)
- **Rate Limiting**: Flask-Limiter + Redis
- **Documentation**: Flasgger (Swagger UI)
- **Deployment**: Docker + Gunicorn
- **Migrations**: Flask-Migrate (Alembic)

---

## 🎓 Summary

This is a **well-structured Flask authentication system** with:
- Complete user management
- JWT authentication
- Role-based permissions
- OAuth support
- Rate limiting
- API documentation

**Main Issue**: Email functionality is configured but not implemented - emails are never sent.

**Next Steps**: 
1. Understand the system (you're doing this now!)
2. Decide if you want to fix email or migrate to Supabase
3. Make improvements based on your needs

---

## 📝 Quick Reference

- **API Base URL**: `http://localhost:5001`
- **Swagger Docs**: `http://localhost:5001/docs`
- **Database**: `instance/app.db` (SQLite) or PostgreSQL
- **Redis**: `localhost:6379` (for rate limiting)
- **Port**: `5001`

---

**Questions?** Check the code or ask me to explain any specific part!

