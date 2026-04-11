#!/usr/bin/env python3
"""Run with: cd backend && python smoke_test.py — uses isolated SQLite under backend/tests/."""
from __future__ import annotations

import os
import sys
from pathlib import Path

_backend = Path(__file__).resolve().parent
_db = _backend / "tests" / "_smoke_app.db"
_db.parent.mkdir(parents=True, exist_ok=True)
if _db.exists():
    _db.unlink()

os.environ["DATABASE_URL"] = f"sqlite:///{_db.as_posix()}"
# Do not load stale modules from a prior import
sys.path.insert(0, str(_backend))

from fastapi.testclient import TestClient  # noqa: E402

from run import app  # noqa: E402


def main() -> None:
    with TestClient(app) as client:
        _run(client)


def _run(client: TestClient) -> None:
    r = client.get("/api/health")
    assert r.status_code == 200, r.text

    r = client.get("/api/me")
    assert r.status_code == 403, r.text

    r = client.post("/auth/refresh")
    assert r.status_code == 401, r.text

    r = client.post(
        "/auth/signup",
        json={
            "username": "smoke_user",
            "email": "smoke@example.com",
            "password": "securepass1",
        },
    )
    assert r.status_code == 201, r.text

    r = client.post(
        "/auth/signup",
        json={
            "username": "smoke_user",
            "email": "smoke@example.com",
            "password": "securepass1",
        },
    )
    assert r.status_code == 400, r.text

    r = client.post(
        "/auth/login",
        json={"email": "smoke@example.com", "password": "wrongpassword"},
    )
    assert r.status_code == 401, r.text

    r = client.post(
        "/auth/login",
        json={"email": "smoke@example.com", "password": "securepass1"},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    access, refresh = data["access_token"], data["refresh_token"]

    r = client.post("/auth/refresh", headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 401, r.text

    r = client.get("/api/me", headers={"Authorization": f"Bearer {access}"})
    assert r.status_code == 200, r.text

    r = client.post("/auth/refresh", headers={"Authorization": f"Bearer {refresh}"})
    assert r.status_code == 200, r.text
    new_access = r.json()["access_token"]

    r = client.post("/auth/logout", headers={"Authorization": f"Bearer {new_access}"})
    assert r.status_code == 200, r.text

    r = client.get("/api/me", headers={"Authorization": f"Bearer {new_access}"})
    assert r.status_code == 401, r.text

    # OAuth: either not configured (501) or redirect to provider (3xx)
    for path in ("/auth/google", "/auth/github"):
        r = client.get(path, follow_redirects=False)
        assert r.status_code in (301, 302, 303, 307, 308, 501), f"{path}: {r.status_code} {r.text}"

    print("smoke_test OK")


if __name__ == "__main__":
    main()
