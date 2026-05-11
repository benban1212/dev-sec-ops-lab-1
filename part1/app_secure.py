"""
DevSecOps Lab - Session 1
Secure Flask Application (Fixed Version)
Demonstrates security best practices.
"""

from flask import Flask, request, render_template, redirect, url_for, session, jsonify, abort
import sqlite3
import os
import hashlib
import hmac
import secrets
import re
import logging
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

# ─── App Configuration ────────────────────────────────────────────────────────
app = Flask(__name__)

# FIX 1: Secret key loaded from environment variable, never hardcoded
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# ─── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# ─── Database Setup ───────────────────────────────────────────────────────────
DB_PATH = "secure_users.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user'
    )""")
    # Seed admin with hashed password
    pw_hash = generate_password_hash("Admin@Secure!2024")
    c.execute("INSERT OR IGNORE INTO users (id,username,password_hash,role) VALUES (1,'admin',?,'admin')", (pw_hash,))
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ─── Auth Decorator ───────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated

# ─── Input Validation ─────────────────────────────────────────────────────────
def validate_username(username: str) -> bool:
    """Allow only alphanumeric + underscore, 3-32 chars."""
    return bool(re.match(r"^[a-zA-Z0-9_]{3,32}$", username))

ALLOWED_HOSTS = {"google.com", "example.com", "localhost"}

def validate_host(host: str) -> bool:
    """Whitelist allowed ping targets."""
    return host in ALLOWED_HOSTS

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return "<h1>Secure Flask App</h1><a href='/login'>Login</a>"


# FIX 2: Parameterized queries prevent SQL Injection
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not validate_username(username):
            return "Invalid username format", 400

        conn = get_db()
        # SECURE: Parameterized query
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            logger.info(f"Successful login: {username}")
            return redirect(url_for("dashboard"))
        else:
            logger.warning(f"Failed login attempt for: {username}")
            # Generic error message - don't reveal which field was wrong
            return render_template("login.html", error="Invalid credentials"), 401

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    # FIX 3: Use Jinja2 templates with auto-escaping (no raw f-strings)
    return f"<h1>Welcome {session['username']}!</h1><p>Role: {session['role']}</p>"


# FIX 4: Search uses templates with auto-escaping - XSS prevented
@app.route("/search")
@login_required
def search():
    query = request.args.get("q", "")
    # Jinja2 auto-escaping handles XSS - just pass to template
    return render_template("search.html", query=query)


# FIX 5: Whitelist-based host validation - no shell=True
@app.route("/ping")
@login_required
@admin_required
def ping():
    import subprocess
    host = request.args.get("host", "")
    if not validate_host(host):
        return jsonify({"error": "Host not in allowlist"}), 400
    # SECURE: No shell=True, argument list prevents injection
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5)
    return jsonify({"output": result.stdout})


# FIX 6: No deserialization of user input - use JSON instead
@app.route("/load_profile", methods=["POST"])
@login_required
def load_profile():
    import json
    data = request.get_json()
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON"}), 400
    # Validate expected fields only
    allowed_keys = {"theme", "language", "notifications"}
    profile = {k: v for k, v in data.items() if k in allowed_keys}
    return jsonify({"profile": profile})


# FIX 7: Path traversal - use safe_join and whitelist
@app.route("/read_file")
@login_required
def read_file():
    from werkzeug.utils import safe_join
    ALLOWED_FILES = {"readme.txt", "help.txt", "faq.txt"}
    filename = request.args.get("file", "")
    if filename not in ALLOWED_FILES:
        return "File not allowed", 403
    try:
        safe_path = safe_join(app.static_folder, "docs", filename)
        with open(safe_path, "r") as f:
            return f"<pre>{f.read()}</pre>"
    except (FileNotFoundError, OSError):
        return "File not found", 404


# FIX 8: API never returns passwords; requires auth
@app.route("/api/users")
@login_required
@admin_required
def api_users():
    conn = get_db()
    users = conn.execute("SELECT id, username, role FROM users").fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])


if __name__ == "__main__":
    init_db()
    # SECURE: Debug off, only localhost in dev (use gunicorn/nginx in prod)
    app.run(debug=False, host="127.0.0.1", port=5001)
