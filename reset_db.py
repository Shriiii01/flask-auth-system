from flask_auth import create_app, db
from flask_auth.models import User, Role
import time
from datetime import datetime

def reset_db():
    app = create_app()
    with app.app_context():
        print("Dropping all tables...")
        db.drop_all()
        
        print("Creating all tables...")
        db.create_all()
        
        print("Creating admin role...")
        admin_role = Role(name="admin", description="Administrator with full access")
        db.session.add(admin_role)
        db.session.commit()
        
        print("Creating admin user...")
        admin = User(
            username="shri",
            email="shri@example.com",
            is_active=True,
            is_verified=True,
            token_revoked_at=datetime.utcnow()
        )
        admin.set_password("ShriStrong123")
        admin.roles.append(admin_role)
        db.session.add(admin)
        db.session.commit()
        
        print("✅ Database reset complete!")
        print("✅ Admin user created:")
        print(f"Email: shri@example.com")
        print(f"Password: ShriStrong123")
        print("✅ ActivityLog table created")
        print("✅ Token revocation system enabled")

if __name__ == "__main__":
    # Wait for database to be ready
    print("Waiting for database to be ready...")
    time.sleep(5)
    reset_db() 