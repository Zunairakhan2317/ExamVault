"""Flask-client tests for default-deny role authorization and its audit hook."""

from typing import Any

import pytest
from flask import Flask
from flask_login import LoginManager, UserMixin, login_user

from auth.rbac import PERMISSIONS, ROLES, has_permission, role_required, set_denied_handler


class FakeUser(UserMixin):
    """Minimal in-memory authenticated principal for RBAC route tests."""

    def __init__(self, user_id: str, role: str | None) -> None:
        self.id = user_id
        self.role = role


@pytest.fixture
def rbac_app() -> tuple[Flask, list[FakeUser]]:
    """Build a database-free Flask app with login and role-protected routes."""
    users: dict[str, FakeUser] = {}
    app = Flask(__name__)
    app.config.update(SECRET_KEY="rbac-test-secret", TESTING=True)
    login_manager = LoginManager()
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id: str) -> FakeUser | None:
        return users.get(user_id)

    @app.get("/login-as/<role>")
    def login_as(role: str) -> str:
        user = FakeUser(f"user-{len(users) + 1}", None if role == "none" else role)
        users[user.get_id()] = user
        login_user(user)
        return "logged in"

    @app.get("/exam")
    @role_required("examiner")
    def examiner_route() -> str:
        return "examiner"

    @app.get("/multi")
    @role_required("examiner", "auditor")
    def multi_role_route() -> str:
        return "allowed"

    @app.get("/admin")
    @role_required("admin")
    def admin_route() -> str:
        return "admin"

    return app, list(users.values())


@pytest.fixture(autouse=True)
def reset_denied_handler() -> Any:
    """Prevent registered audit callbacks from leaking between tests."""
    set_denied_handler(None)
    yield
    set_denied_handler(None)

def test_anonymous_wrong_role_and_correct_role_statuses(rbac_app: tuple[Flask, list[FakeUser]]) -> None:
    """Protected routes deny anonymous/wrong roles and allow the required role."""
    app, _ = rbac_app
    client = app.test_client()

    assert client.get("/exam").status_code == 401
    assert client.get("/login-as/auditor").status_code == 200
    assert client.get("/exam").status_code == 403
    assert client.get("/login-as/examiner").status_code == 200
    assert client.get("/exam").status_code == 200


def test_multi_role_route_allows_each_listed_role_and_rejects_others(
    rbac_app: tuple[Flask, list[FakeUser]],
) -> None:
    """A route accepts each explicitly listed role and denies every other role."""
    app, _ = rbac_app
    client = app.test_client()

    for role in ("examiner", "auditor"):
        assert client.get(f"/login-as/{role}").status_code == 200
        assert client.get("/multi").status_code == 200
    for role in ("admin", "invigilator", "superuser"):
        assert client.get(f"/login-as/{role}").status_code == 200
        assert client.get("/multi").status_code == 403


@pytest.mark.parametrize("role", ["none", "superuser"])
def test_none_or_unknown_user_role_is_denied(
    rbac_app: tuple[Flask, list[FakeUser]],
    role: str,
) -> None:
    """Missing and unrecognized role values receive default-deny behavior."""
    app, _ = rbac_app
    client = app.test_client()

    assert client.get(f"/login-as/{role}").status_code == 200
    assert client.get("/admin").status_code == 403


def test_role_required_rejects_empty_or_unknown_roles_at_decoration_time() -> None:
    """Role typos and empty protection declarations fail during application setup."""
    with pytest.raises(ValueError):
        role_required()
    with pytest.raises(ValueError):
        role_required("admn")


def test_has_permission_matches_explicit_role_matrix() -> None:
    """Every role-permission combination follows the reviewed least-privilege matrix."""
    expected_permissions = {
        "admin": {
            "manage_users", "revoke_users", "rotate_shares", "view_alerts",
            "view_dashboard", "view_files", "view_demo",
        },
        "examiner": {
            "upload_exam", "manage_exams", "run_leak_analyzer",
            "view_dashboard", "view_files", "view_demo",
        },
        "invigilator": {
            "submit_share", "download_copy", "view_exam_status",
            "view_dashboard", "view_files", "view_demo",
        },
        "auditor": {
            "view_audit_log", "run_verifier", "view_daily_roots",
            "run_leak_analyzer", "view_dashboard", "view_files", "view_demo",
        },
    }

    assert set(ROLES) == set(expected_permissions)
    assert set(PERMISSIONS) == set().union(*expected_permissions.values())
    for role, expected in expected_permissions.items():
        for permission in PERMISSIONS:
            assert has_permission(role, permission) is (permission in expected)


def test_has_permission_fails_closed_for_unknown_inputs() -> None:
    """Unknown and non-string role/permission inputs never grant access."""
    assert not has_permission(None, "view_dashboard")
    assert not has_permission("admin", "unknown")
    assert not has_permission(5, "x")
    assert not has_permission("admin", None)


def test_denied_handler_receives_only_required_safe_fields_and_reasons(
    rbac_app: tuple[Flask, list[FakeUser]],
) -> None:
    """Denial callbacks receive the exact minimal fields for unauthenticated and role denials."""
    app, _ = rbac_app
    calls: list[dict[str, Any]] = []
    set_denied_handler(calls.append)
    client = app.test_client()
    assert client.get("/exam").status_code == 401
    assert client.get("/login-as/auditor").status_code == 200
    assert client.get("/exam").status_code == 403

    expected_keys = {"user_id", "role", "required", "path", "method", "reason"}
    assert len(calls) == 2
    assert all(set(call) == expected_keys for call in calls)
    assert calls[0] == {
        "user_id": None,
        "role": None,
        "required": ("examiner",),
        "path": "/exam",
        "method": "GET",
        "reason": "unauthenticated",
    }
    assert calls[1] == {
        "user_id": "user-1",
        "role": "auditor",
        "required": ("examiner",),
        "path": "/exam",
        "method": "GET",
        "reason": "wrong_role",
    }


def test_raising_denied_handler_does_not_change_forbidden_response(
    rbac_app: tuple[Flask, list[FakeUser]],
) -> None:
    """Audit-hook failures are swallowed while access remains denied."""
    app, _ = rbac_app

    def broken_handler(denial: dict[str, Any]) -> None:
        raise RuntimeError("audit unavailable")

    set_denied_handler(broken_handler)
    client = app.test_client()
    assert client.get("/login-as/auditor").status_code == 200
    assert client.get("/exam").status_code == 403


def test_setting_denied_handler_to_none_stops_callbacks(
    rbac_app: tuple[Flask, list[FakeUser]],
) -> None:
    """Passing None unregisters the hook and prevents future callback calls."""
    app, _ = rbac_app
    calls: list[dict[str, Any]] = []
    set_denied_handler(calls.append)
    set_denied_handler(None)

    assert app.test_client().get("/exam").status_code == 401
    assert calls == []
