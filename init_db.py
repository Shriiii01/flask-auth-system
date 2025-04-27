from flask_auth import create_app, db
from flask_auth.models import User, Role
import time

def init_db():
    try:
        app = create_app()
        with app.app_context():
            print("Attempting to connect to database...")
            try:
                db.engine.connect()
                print("Successfully connected to database")
            except Exception as e:
                print(f"Error connecting to database: {str(e)}")
                return

            print("Dropping all tables...")
            db.drop_all()
            print("Creating all tables...")
            db.create_all()
            
            print("Creating admin role...")
            admin_role = Role(name="admin")
            db.session.add(admin_role)
            db.session.commit()
            
            print("Creating admin user...")
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
            
            print("Database initialized")
            print("Admin user created:")
            print(f"Email: shri@example.com")
            print(f"Password: ShriStrong123")
            
            user = User.query.filter_by(email="shri@example.com").first()
            if user and admin_role in user.roles:
                print("Admin role assigned correctly")
            else:
                print("Error: Admin role not assigned")
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        raise e

if __name__ == "__main__":
    print("Waiting for database to be ready...")
    time.sleep(5)
    init_db() 