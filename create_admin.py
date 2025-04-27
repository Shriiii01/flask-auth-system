from flask_auth import create_app, db
from flask_auth.models import User
import os

def create_admin_user():
    os.environ['DATABASE_URL'] = 'postgresql://flask_user:Shrijam9@db:5432/flask_auth'
    
    app = create_app()
    with app.app_context():
        try:
            if User.query.filter_by(email="shri@example.com").first():
                print("Admin user already exists")
                return

            admin = User(
                username="shri",
                email="shri@example.com",
                role="admin",
                is_active=True
            )
            admin.set_password("ShriStrong123")
            
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully")
            
            user = User.query.filter_by(email="shri@example.com").first()
            if user:
                print("User verified in database")
                print(f"User ID: {user.id}")
                print(f"Email: {user.email}")
                print(f"Role: {user.role}")
                print(f"Active: {user.is_active}")
            else:
                print("User not found in database after creation")
                
        except Exception as e:
            print(f"Error creating admin user: {str(e)}")
            db.session.rollback()

if __name__ == "__main__":
    create_admin_user() 