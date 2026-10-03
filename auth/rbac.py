"""Role-based authorization with a minimal hook for reporting denied requests."""

from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar, cast

from flask import abort, request
from flask_login import current_user

ROLES = ("admin", "examiner", "invigilator", "auditor")

PERMISSIONS: dict[str, frozenset[str]] = {
    "manage_users": frozenset({"admin"}),
    "revoke_users": frozenset({"admin"}),
    "rotate_shares": frozenset({"admin"}),
    "view_alerts": frozenset({"admin"}),
    "upload_exam": frozenset({"examiner"}),
    "manage_exams": frozenset({"examiner"}),
    "submit_share": frozenset({"invigilator"}),
    "download_copy": frozenset({"invigilator"}),
    "view_exam_status": frozenset({"invigilator"}),
    "view_audit_log": frozenset({"auditor"}),
    "run_verifier": frozenset({"auditor"}),
    "view_daily_roots": frozenset({"auditor"}),
    "run_leak_analyzer": frozenset({"examiner", "auditor"}),
    "view_dashboard": frozenset(ROLES),
    "view_files": frozenset(ROLES),
    "view_demo": frozenset(ROLES),
}

_DeniedHandler = Callable[[dict[str, Any]], None]
_denied_handler: _DeniedHandler | None = None
_View = TypeVar("_View", bound=Callable[..., Any])


def has_permission(role: object, permission: object) -> bool:
    """Return whether a recognized role may perform a permission, defaulting to deny."""
    if not isinstance(role, str) or not isinstance(permission, str):
        return False
    return role in ROLES and role in PERMISSIONS.get(permission, frozenset())


def set_denied_handler(handler: _DeniedHandler | None) -> None:
    """Register the callback that lets the web layer audit authorization denials."""
    if handler is not None and not callable(handler):
        raise TypeError("handler must be callable or None")
    global _denied_handler
    _denied_handler = handler


def _report_denial(required: tuple[str, ...], reason: str) -> None:
    """Send only minimal request identity and authorization metadata to the hook."""
    if _denied_handler is None:
        return
    authenticated = bool(getattr(current_user, "is_authenticated", False))
    user_id = current_user.get_id() if authenticated else None
    denial = {
        "user_id": user_id,
        "role": getattr(current_user, "role", None) if authenticated else None,
        "required": required,
        "path": request.path,
        "method": request.method,
        "reason": reason,
    }
    try:
        _denied_handler(denial)
    except Exception:
        # Authorization denial must not become an application error if logging fails.
        pass


def role_required(*roles: str) -> Callable[[_View], _View]:
    """Protect a Flask view by role and report every denied request to the audit hook."""
    if not roles:
        raise ValueError("at least one role is required")
    if any(not isinstance(role, str) or role not in ROLES for role in roles):
        raise ValueError("all required roles must be recognized roles")

    def decorator(view: _View) -> _View:
        @wraps(view)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            if not bool(getattr(current_user, "is_authenticated", False)):
                _report_denial(roles, "unauthenticated")
                abort(401)
            if getattr(current_user, "role", None) not in roles:
                _report_denial(roles, "wrong_role")
                abort(403)
            return view(*args, **kwargs)

        return cast(_View, wrapped)

    return decorator
