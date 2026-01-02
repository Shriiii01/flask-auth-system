# 🚀 Database Setup Guide

## Current Status

✅ **Code is ready!** The signup and login routes are configured to store emails and passwords in Supabase.

## What You Need to Do

### Step 1: Get Your Supabase Database Password

1. Go to [Supabase Dashboard](https://app.supabase.com)
2. Select your project: `shbmmpyqbojzwafpnetk`
3. Go to **Settings** → **Database**
4. Find your **Database password** (or reset it if needed)

### Step 2: Update .env File

Replace `[YOUR-PASSWORD]` in your `.env` file with your actual password:

```bash
DATABASE_URL=postgresql://postgres:YOUR_ACTUAL_PASSWORD_HERE@db.shbmmpyqbojzwafpnetk.supabase.co:5432/postgres
```

**Example:**
```bash
DATABASE_URL=postgresql://postgres:MySecurePassword123@db.shbmmpyqbojzwafpnetk.supabase.co:5432/postgres
```

### Step 3: Initialize Database Tables

Run this command to create the `user` table in Supabase:

```bash
python backend/init_db.py
```

You should see:
```
✅ Database tables created successfully!
📋 Created tables:
   - user (stores email, username, password_hash)
```

### Step 4: Start the Server

```bash
python run.py
```

### Step 5: Test Signup & Login

1. Visit: http://localhost:5001
2. Sign up with email and password
3. Login with your credentials
4. Check Supabase Dashboard → **Table Editor** → **user** table to see your data!

## What Gets Stored

When a user signs up, the system stores:
- ✅ **email** - User's email address
- ✅ **username** - User's username
- ✅ **password_hash** - Encrypted password (bcrypt)
- ✅ **is_active** - Account status
- ✅ **created_at** - Registration timestamp

**Passwords are NEVER stored in plain text!** They are hashed using bcrypt.

## Verify Data Storage

1. Go to Supabase Dashboard
2. Navigate to **Table Editor**
3. Click on **user** table
4. You should see all registered users with their emails and hashed passwords

## Troubleshooting

**Error: "DATABASE_URL not set or contains placeholder"**
- Make sure you replaced `[YOUR-PASSWORD]` with your actual password

**Error: "Connection refused" or "Authentication failed"**
- Check your Supabase password is correct
- Verify your Supabase project is active
- Check your internet connection

**Error: "Table already exists"**
- That's fine! The tables are already created
- You can proceed to sign up/login

