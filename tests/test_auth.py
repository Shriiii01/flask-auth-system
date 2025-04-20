from flask_auth.models import User, Role, db

def verify_user(client, email):
    with client.application.app_context():
        user = User.query.filter_by(email=email).first()
        user.is_verified = True
        db.session.commit()

def test_login_user(client):
    client.post("/auth/register", json={
        "username": "testuser2",
        "email": "test2@example.com",
        "password": "testpass123"
    })
    verify_user(client, "test2@example.com")

    response = client.post("/auth/login", json={
        "email": "test2@example.com",
        "password": "testpass123"
    })

    assert response.status_code == 200
    assert "access_token" in response.json

def test_refresh_token(client):
    client.post("/auth/register", json={
        "username": "refreshuser",
        "email": "refresh@example.com",
        "password": "refresh123"
    })
    verify_user(client, "refresh@example.com")

    login_res = client.post("/auth/login", json={
        "email": "refresh@example.com",
        "password": "refresh123"
    })

    refresh_token = login_res.json["refresh_token"]

    res = client.post("/auth/refresh", headers={
        "Authorization": f"Bearer {refresh_token}"
    })

    assert res.status_code == 200
    assert "access_token" in res.json

def test_protected_route(client):
    client.post("/auth/register", json={
        "username": "secureuser",
        "email": "secure@example.com",
        "password": "secure123"
    })
    verify_user(client, "secure@example.com")

    login_res = client.post("/auth/login", json={
        "email": "secure@example.com",
        "password": "secure123"
    })

    token = login_res.json["access_token"]

    protected = client.get("/auth/protected", headers={
        "Authorization": f"Bearer {token}"
    })

    assert protected.status_code == 200

def test_admin_role_create(client, app):
    with app.app_context():
        admin = User(username="admin", email="admin@example.com", is_verified=True)
        admin.set_password("admin123")
        admin_role = Role.query.filter_by(name="admin").first()
        if not admin_role:
            admin_role = Role(name="admin")
        db.session.add(admin)
        db.session.add(admin_role)
        admin.roles.append(admin_role)
        db.session.commit()

    login_res = client.post("/auth/login", json={
        "email": "admin@example.com",
        "password": "admin123"
    })

    token = login_res.json["access_token"]

    res = client.post("/admin/roles", json={
        "name": "tester"
    }, headers={
        "Authorization": f"Bearer {token}"
    })

    assert res.status_code == 201

def test_logout_token_revoked(client):
    client.post("/auth/register", json={
        "username": "logoutuser",
        "email": "logout@example.com",
        "password": "logout123"
    })
    verify_user(client, "logout@example.com")

    login_res = client.post("/auth/login", json={
        "email": "logout@example.com",
        "password": "logout123"
    })

    token = login_res.json["access_token"]

    client.post("/auth/logout", headers={
        "Authorization": f"Bearer {token}"
    })

    # Token should now be rejected
    res = client.get("/auth/protected", headers={
        "Authorization": f"Bearer {token}"
    })

    assert res.status_code == 401