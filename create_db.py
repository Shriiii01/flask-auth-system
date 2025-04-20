from flask_auth import create_app, db
from flask_auth.models import User, Role

app = create_app()

with app.app_context():
    db.create_all()
    print("Database tables created successfully!") 