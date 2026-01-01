# Supabase Database Setup Guide

## Quick Start

This FastAPI authentication system now uses **Supabase PostgreSQL** as the database.

## 1. Get Your Supabase Connection String

1. Go to [supabase.com](https://supabase.com) and create a project
2. Navigate to **Settings** → **Database**
3. Find your **Connection string** (URI format)
4. Copy the connection string

### Connection String Formats:

**Direct Connection:**
```
postgresql://postgres:[YOUR-PASSWORD]@db.[YOUR-PROJECT-REF].supabase.co:5432/postgres
```

**Connection Pooling (Recommended for production):**
```
postgresql://postgres.[YOUR-PROJECT-REF]:[YOUR-PASSWORD]@aws-0-[region].pooler.supabase.com:6543/postgres
```

## 2. Set Environment Variables

Create a `.env` file in the project root:

```bash
# Supabase Database Connection
DATABASE_URL=postgresql://postgres:[YOUR-PASSWORD]@db.[YOUR-PROJECT-REF].supabase.co:5432/postgres

# Or use SUPABASE_DATABASE_URL
SUPABASE_DATABASE_URL=postgresql://postgres.[YOUR-PROJECT-REF]:[YOUR-PASSWORD]@aws-0-[region].pooler.supabase.com:6543/postgres

# Optional: Supabase Client Settings
SUPABASE_URL=https://[YOUR-PROJECT-REF].supabase.co
SUPABASE_KEY=your-anon-key
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key

# Other settings
SECRET_KEY=your-secret-key
JWT_SECRET_KEY=your-jwt-secret-key
BASE_URL=http://localhost:5001
REDIS_URL=redis://localhost:6379/0
```

## 3. Run Database Migrations

```bash
# Initialize Alembic (if not already done)
alembic init migrations

# Create a migration
alembic revision --autogenerate -m "Initial migration"

# Apply migrations to Supabase
alembic upgrade head
```

## 4. Verify Connection

The application will automatically connect to Supabase when you start it:

```bash
python run.py
```

Check the logs to confirm the database connection is successful.

## Benefits of Using Supabase

✅ **Managed PostgreSQL** - No database server management  
✅ **Auto-scaling** - Handles traffic spikes automatically  
✅ **Backups** - Automatic daily backups  
✅ **Connection Pooling** - Built-in connection pooling  
✅ **SSL/TLS** - Secure connections by default  
✅ **Free Tier** - Generous free tier (500MB database, 2GB bandwidth)  

## Troubleshooting

### Connection Issues

1. **Check your connection string** - Make sure password is URL-encoded
2. **Verify network access** - Supabase allows connections from anywhere by default
3. **Check SSL mode** - The code automatically sets `sslmode=require` for Supabase

### Migration Issues

If migrations fail:
```bash
# Check current migration status
alembic current

# View migration history
alembic history

# Rollback if needed
alembic downgrade -1
```

## Production Recommendations

1. **Use Connection Pooling** - Use the pooler URL for better performance
2. **Set up backups** - Supabase handles this automatically
3. **Monitor usage** - Check your Supabase dashboard for usage metrics
4. **Use environment variables** - Never commit connection strings to git

## Migration from SQLite

If you were using SQLite before:

1. Export your data from SQLite
2. Set up Supabase project
3. Run migrations on Supabase
4. Import your data (if needed)
5. Update `DATABASE_URL` environment variable

## Support

- [Supabase Documentation](https://supabase.com/docs)
- [Supabase Discord](https://discord.supabase.com)
- [Supabase GitHub](https://github.com/supabase/supabase)

