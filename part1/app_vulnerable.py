"""
DevSecOps Lab - Session 1
Vulnerable Flask Application (Intentionally Insecure for Learning)
WARNING: DO NOT deploy this in production!
"""

from flask import Flask, request, render_template_string, redirect, jsonify
import sqlite3
import os
import subprocess
import pickle
import base64

app = Flask(__name__)
app.secret_key = "supersecretkey123"  # VULNERABILITY: Hardcoded secret

# ─── Database Setup ───────────────────────────────────────────────────────────
DB_PATH = "users.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,
        role TEXT
    )""")
    # Seed data
    c.execute("INSERT OR IGNORE INTO users VALUES (1,'admin','admin123','admin')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2,'alice','password','user')")
    conn.commit()
    conn.close()

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return "<h1>Vulnerable Flask App</h1><a href='/login'>Login</a>"


# VULNERABILITY 1: SQL Injection
@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        # VULNERABLE: Direct string interpolation → SQL Injection
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        print(f"[DEBUG] Query: {query}")
        c.execute(query)
        user = c.fetchone()
        conn.close()

        if user:
            return f"<h1>Welcome {user[1]}! Role: {user[3]}</h1>"
        else:
            error = "Invalid credentials"

    return render_template_string("""
    <form method='POST'>
        Username: <input name='username'><br>
        Password: <input type='password' name='password'><br>
        <input type='submit' value='Login'>
        <p style='color:red'>{{ error }}</p>
    </form>
    <p>Hint: Try <code>' OR '1'='1</code> as username</p>
    """, error=error)


# VULNERABILITY 2: XSS (Cross-Site Scripting)
@app.route("/search")
def search():
    query = request.args.get("q", "")
    # VULNERABLE: User input reflected without escaping
    return f"<h1>Search results for: {query}</h1><p>No results found.</p>"


# VULNERABILITY 3: Command Injection
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # VULNERABLE: OS command injection
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return f"<pre>{result.stdout}\n{result.stderr}</pre>"


# VULNERABILITY 4: Insecure Deserialization
@app.route("/load_profile", methods=["POST"])
def load_profile():
    data = request.form.get("data", "")
    # VULNERABLE: Unpickling untrusted data
    obj = pickle.loads(base64.b64decode(data))
    return jsonify({"profile": str(obj)})


# VULNERABILITY 5: Path Traversal
@app.route("/read_file")
def read_file():
    filename = request.args.get("file", "readme.txt")
    # VULNERABLE: No path sanitization
    with open(filename, "r") as f:
        return f"<pre>{f.read()}</pre>"


# VULNERABILITY 6: Sensitive Data Exposure
@app.route("/api/users")
def api_users():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # VULNERABLE: Exposes all user data including passwords
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    conn.close()
    return jsonify(users)


if __name__ == "__main__":
    init_db()
    # VULNERABILITY: Debug mode + exposed on all interfaces
    app.run(debug=True, host="0.0.0.0", port=5000)
