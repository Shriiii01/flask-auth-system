# 🚀 Quick Start Guide - Understanding Your System

## What You Have

You have a **Flask Authentication API** - a backend server that handles:
- User registration and login
- JWT token authentication
- Role-based permissions (admin, user, etc.)
- User management
- OAuth (GitHub login)

---

## 🗺️ System Map

```
┌─────────────────────────────────────────────────────────────┐
│                    YOUR FLASK APP                            │
│              (Running on http://localhost:5001)              │
└─────────────────────────────────────────────────────────────┘
                            │
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
   ┌─────────┐        ┌─────────┐        ┌─────────┐
   │Database │        │ Redis   │        │  SMTP   │
   │         │        │(Rate    │        │(Email)  │
   │ Users   │        │Limit)   │        │ ❌ BROKEN│
   │ Roles   │        │         │        │         │
   │ Logs    │        │         │        │         │
   └─────────┘        └─────────┘        └─────────┘
```

---

## 📍 Where Everything Is Stored

### 1. **User Data** (Emails, Passwords, Usernames)
- **Location**: Database (`instance/app.db` if SQLite, or PostgreSQL)
- **Table**: `user` table
- **Contains**: 
  - Email addresses
  - Username
  - Password (hashed, not plain text!)
  - Verification status
  - Roles assigned

### 2. **Roles & Permissions**
- **Location**: Database
- **Table**: `role` table + `user_roles` (linking table)
- **Contains**: Admin, Editor, User roles

### 3. **Activity Logs**
- **Location**: Database
- **Table**: `activity_log` table
- **Contains**: Who did what, when

### 4. **JWT Tokens**
- **Location**: Not stored in database (stateless)
- **How it works**: Tokens are generated and validated, not stored
- **Exception**: Token revocation info stored in `token` table

---

## 🔄 How Data Flows

### Example: User Registers

```
1. User fills form → Frontend sends POST /auth/register
   {
     "username": "john",
     "email": "john@example.com",
     "password": "secret123"
   }

2. Flask receives request
   ↓
3. Checks database: Does email exist? Does username exist?
   ↓
4. Creates new User record in database
   - Stores: username, email, password_hash (encrypted!)
   - Sets: is_verified = False
   - Generates: email_verification_token
   ↓
5. Returns verification link
   {
     "verification_link": "http://localhost:5001/auth/verify-email/abc123..."
   }
   
   ⚠️ PROBLEM: Email is NOT sent! User must manually copy link!
```

### Example: User Logs In

```
1. User sends POST /auth/login
   {
     "email": "john@example.com",
     "password": "secret123"
   }

2. Flask checks database
   ↓
3. Finds user by email
   ↓
4. Compares password_hash with provided password
   ↓
5. If correct, generates JWT tokens
   ↓
6. Returns tokens
   {
     "access_token": "eyJhbGc...",
     "refresh_token": "eyJhbGc...",
     "user": {...}
   }
```

---

## 🗂️ File Structure Explained

### Core Files:

1. **`flask_auth/__init__.py`**
   - Creates the Flask app
   - Sets up everything
   - Registers routes

2. **`flask_auth/models.py`**
   - Defines database tables
   - User, Role, ActivityLog, Token models

3. **`flask_auth/routes/auth.py`**
   - Login, register, logout endpoints
   - Password reset endpoints

4. **`flask_auth/routes/admin_routes.py`**
   - Admin-only endpoints
   - User management, role management

5. **`config.py`**
   - All settings (database URL, secrets, etc.)

---

## 🔐 Security Features

1. **Passwords**: Stored as hashes (can't be reversed)
2. **JWT Tokens**: Secure, signed tokens
3. **Rate Limiting**: Prevents brute-force attacks
4. **Email Verification**: Users must verify (but emails not sent!)
5. **Role-Based Access**: Different permissions for different roles

---

## ⚠️ Current Issues

1. **Email Not Working**
   - Configuration exists
   - But no code to actually send emails
   - Users can't receive verification emails

2. **Database Defaults to SQLite**
   - Fine for development
   - Not ideal for production
   - Should use PostgreSQL

---

## 🎯 What You Can Do Now

### Test the API:
1. Start the server: `python run.py`
2. Go to: `http://localhost:5001/docs`
3. Try registering a user
4. Copy the verification link manually
5. Login with the user

### Check the Database:
- SQLite: `instance/app.db` (if using SQLite)
- Use a SQLite browser to view data

### View Logs:
- Check console output
- See what's happening

---

## 📚 Next Steps

1. ✅ **Understand the system** (you're doing this!)
2. **Decide**: Fix email OR migrate to Supabase?
3. **Test**: Try the API endpoints
4. **Improve**: Add features you need

---

## 💡 Key Concepts

- **JWT Tokens**: Like a temporary ID card that proves you're logged in
- **Roles**: Different permission levels (admin can do more than regular user)
- **Rate Limiting**: Prevents too many requests (security)
- **Database**: Where all user data lives
- **API Endpoints**: URLs you call to do things (like `/auth/login`)

---

**Need more details?** Check `SYSTEM_OVERVIEW.md` for complete documentation!

