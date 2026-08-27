"""Minimal session login for the dashboard.

Single operator account (`UNINET_AUTH_USER` / `UNINET_AUTH_PASSWORD`, defaults
admin / uninet). This gates the console UI and API - it is not a user-management
system. Set `UNINET_AUTH_DISABLED=1` for open local dev.
"""
from __future__ import annotations

import hmac
from functools import wraps

from flask import (
    Blueprint,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

bp = Blueprint("auth", __name__)


def _settings():
    return current_app.config["SETTINGS"]


def check_credentials(user: str, password: str) -> bool:
    s = _settings()
    return hmac.compare_digest(user or "", s.auth_user) and hmac.compare_digest(
        password or "", s.auth_password
    )


def is_authenticated() -> bool:
    return _settings().auth_disabled or session.get("user") is not None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if is_authenticated():
            return view(*args, **kwargs)
        if request.path.startswith("/api/"):
            return jsonify(error="authentication required"), 401
        return redirect(url_for("auth.login", next=request.path))

    return wrapped


@bp.get("/login")
def login():
    if is_authenticated():
        return redirect(url_for("index"))
    return render_template("login.html", error=None, next=request.args.get("next", "/"))


@bp.post("/login")
def do_login():
    user = request.form.get("username", "")
    password = request.form.get("password", "")
    nxt = request.form.get("next") or "/"
    if check_credentials(user, password):
        session["user"] = user
        session.permanent = True
        return redirect(nxt if nxt.startswith("/") else "/")
    return render_template("login.html", error="Invalid credentials", next=nxt), 401


@bp.post("/logout")
@bp.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
