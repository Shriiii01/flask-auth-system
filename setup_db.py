from flask_auth import create_app, db
from flask_auth.models import User, Role
from flask_migrate import upgrade

def setup_db():
    app = create_app()
    with app.app_context():
        # Run migrations
        upgrade()
        
        # Create admin role
        admin_role = Role(name="admin")
        db.session.add(admin_role)
        db.session.commit()
        
        # Create admin user
        admin = User(
            username="shri",
            email="shri@example.com",
            is_active=True,
            is_verified=True
        )
        admin.set_password("ShriStrong123")
        admin.roles.append(admin_role)
        db.session.add(admin)
        db.session.commit()
        
        print("✅ Database initialized!")
        print("✅ Admin user created:")
        print(f"Email: shri@example.com")
        print(f"Password: ShriStrong123")

if __name__ == "__main__":
    setup_db() 