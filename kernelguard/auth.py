"""Local administrator sessions using Flask and Werkzeug; no default credentials."""
import os
import re
import secrets
import time
from collections import deque
from datetime import timedelta
from threading import Lock
from flask import abort, g, redirect, render_template, request, session, url_for
from sqlalchemy import select, func
from werkzeug.security import check_password_hash, generate_password_hash
from .core import administrators


def create_administrator(conn, username, password):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", username):
        raise ValueError("Username must contain 1–64 letters, numbers, underscores, dots or hyphens")
    if not 12 <= len(password) <= 256:
        raise ValueError("Use a password containing 12–256 characters")
    if conn.execute(select(administrators.c.id).where(
            administrators.c.username == username)).scalar() is not None:
        raise ValueError("That administrator already exists")
    conn.execute(administrators.insert().values(username=username,
        password_hash=generate_password_hash(password)))


def configure_auth(app, engine, secret_key=None):
    with engine.connect() as conn:
        enabled = bool(conn.execute(select(func.count()).select_from(administrators)).scalar())
    secret = secret_key or os.environ.get("KERNELGUARD_SECRET_KEY")
    if enabled and (not secret or len(secret) < 32):
        raise ValueError("Set KERNELGUARD_SECRET_KEY to a random secret of at least 32 characters before serving")
    app.config.update(SECRET_KEY=secret, AUTH_ENABLED=enabled,
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=os.environ.get("KERNELGUARD_HTTPS") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        SESSION_REFRESH_EACH_REQUEST=False, MAX_CONTENT_LENGTH=16384)
    attempts, attempt_lock = deque(), Lock()
    dummy_hash = generate_password_hash(secrets.token_urlsafe(32)) if enabled else ""

    def csrf_token():
        if not enabled:
            return ""
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return session["csrf_token"]

    @app.context_processor
    def identity():
        return dict(administrator=g.get("administrator"), auth_enabled=enabled,
                    csrf_token=csrf_token)

    @app.before_request
    def protect():
        g.administrator = None
        if not enabled:
            if request.method != "GET" and request.method != "HEAD":
                abort(403, "Create an administrator and restart to enable alert review")
            return
        if request.method == "POST":
            supplied, expected = request.form.get("csrf_token", ""), session.get("csrf_token", "")
            if not expected or not secrets.compare_digest(supplied.encode(), expected.encode()):
                abort(400, "Invalid form token; reload the page")
        if "administrator_id" in session:
            with engine.connect() as conn:
                g.administrator = conn.execute(select(administrators.c.id, administrators.c.username)
                    .where(administrators.c.id == session["administrator_id"])).mappings().first()
        if request.endpoint not in ("login", "static") and not g.administrator:
            return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if not enabled:
            return redirect(url_for("dashboard"))
        error = None
        if request.method == "POST":
            now = time.monotonic()
            with attempt_lock:
                while attempts and attempts[0] <= now - 300:
                    attempts.popleft()
                if len(attempts) >= 5:
                    return render_template("login.html", error="Too many attempts. Try again in five minutes."), 429
                attempts.append(now)
            with engine.connect() as conn:
                user = conn.execute(select(administrators).where(administrators.c.username ==
                    request.form.get("username", "")[:64])).mappings().first()
            password = request.form.get("password", "")
            valid = check_password_hash(user["password_hash"] if user else dummy_hash, password[:256])
            if user and valid and len(password) <= 256:
                session.clear()
                session["administrator_id"] = user["id"]
                session.permanent = True
                with attempt_lock:
                    attempts.clear()
                return redirect(url_for("dashboard"))
            error = "Invalid username or password."
        return render_template("login.html", error=error), 401 if error else 200

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))
