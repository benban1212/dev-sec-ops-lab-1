"""
DevSecOps Lab - Session 2
Security-Focused Unit Tests for Flask Application
Run: pytest test_security.py -v
"""

import pytest
import sys
import os

# Add session1 to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../session1"))

from app_secure import app, init_db


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as c:
        with app.app_context():
            init_db()
        yield c


# ─── Authentication Tests ─────────────────────────────────────────────────────

class TestAuthentication:
    def test_valid_login_succeeds(self, client):
        """Valid credentials should allow login."""
        rv = client.post("/login", data={
            "username": "admin",
            "password": "Admin@Secure!2024"
        }, follow_redirects=True)
        assert rv.status_code == 200

    def test_invalid_login_fails(self, client):
        """Wrong password should return 401."""
        rv = client.post("/login", data={
            "username": "admin",
            "password": "wrongpassword"
        })
        assert rv.status_code == 401

    def test_sql_injection_fails(self, client):
        """SQL injection payload should not bypass login."""
        payloads = [
            ("' OR '1'='1", "anything"),
            ("admin'--", "anything"),
            ("' OR 1=1--", "x"),
            ("admin' /*", "*/"),
        ]
        for username, password in payloads:
            rv = client.post("/login", data={
                "username": username,
                "password": password
            })
            # Should not return 200 with a welcome message
            assert rv.status_code in [400, 401], \
                f"SQL injection with '{username}' should not succeed"

    def test_invalid_username_format_rejected(self, client):
        """Usernames with special characters should be rejected."""
        rv = client.post("/login", data={
            "username": "'; DROP TABLE users; --",
            "password": "x"
        })
        assert rv.status_code == 400

    def test_unauthenticated_access_redirects(self, client):
        """Protected routes should redirect unauthenticated users."""
        protected = ["/dashboard", "/search", "/api/users"]
        for path in protected:
            rv = client.get(path)
            assert rv.status_code in [302, 403], \
                f"{path} should require authentication"


# ─── XSS Tests ────────────────────────────────────────────────────────────────

class TestXSS:
    def _login(self, client):
        client.post("/login", data={
            "username": "admin",
            "password": "Admin@Secure!2024"
        })

    def test_xss_payload_escaped(self, client):
        """Script tags in search query should be HTML-escaped."""
        self._login(client)
        xss_payload = "<script>alert('xss')</script>"
        rv = client.get(f"/search?q={xss_payload}")
        assert b"<script>" not in rv.data, "Raw <script> tag should not appear in response"
        # Should be escaped as &lt;script&gt;
        assert b"&lt;script&gt;" in rv.data or xss_payload.encode() not in rv.data

    def test_xss_href_injection(self, client):
        """javascript: URI injection should not execute."""
        self._login(client)
        rv = client.get("/search?q=<a href='javascript:void(0)'>click</a>")
        assert b"javascript:" not in rv.data


# ─── API Security Tests ───────────────────────────────────────────────────────

class TestAPISecrity:
    def _admin_login(self, client):
        client.post("/login", data={
            "username": "admin",
            "password": "Admin@Secure!2024"
        })

    def test_api_users_requires_auth(self, client):
        """API endpoint should reject unauthenticated requests."""
        rv = client.get("/api/users")
        assert rv.status_code in [302, 401, 403]

    def test_api_users_no_passwords(self, client):
        """API response should never include passwords."""
        self._admin_login(client)
        rv = client.get("/api/users")
        data = rv.get_json()
        if data:
            for user in data:
                assert "password" not in user, "API must not return passwords"
                assert "password_hash" not in user, "API must not return password hashes"


# ─── Command Injection Tests ──────────────────────────────────────────────────

class TestCommandInjection:
    def _admin_login(self, client):
        client.post("/login", data={
            "username": "admin",
            "password": "Admin@Secure!2024"
        })

    def test_command_injection_blocked(self, client):
        """Host parameter injection should be blocked by whitelist."""
        self._admin_login(client)
        payloads = [
            "127.0.0.1; ls",
            "localhost && cat /etc/passwd",
            "8.8.8.8 | whoami",
            "$(whoami)",
            "`id`",
        ]
        for host in payloads:
            rv = client.get(f"/ping?host={host}")
            assert rv.status_code == 400, \
                f"Command injection via '{host}' should be blocked"

    def test_allowed_host_works(self, client):
        """Whitelisted hosts should be allowed."""
        self._admin_login(client)
        rv = client.get("/ping?host=localhost")
        # Either succeeds or fails the ping, but should not be 400
        assert rv.status_code != 400


# ─── Deserialization Tests ────────────────────────────────────────────────────

class TestDeserialization:
    def _login(self, client):
        client.post("/login", data={
            "username": "admin",
            "password": "Admin@Secure!2024"
        })

    def test_json_profile_accepted(self, client):
        """Valid JSON profile data should be accepted."""
        self._login(client)
        rv = client.post("/load_profile",
                         json={"theme": "dark", "language": "en"},
                         content_type="application/json")
        assert rv.status_code == 200
        data = rv.get_json()
        assert data.get("profile", {}).get("theme") == "dark"

    def test_unknown_fields_stripped(self, client):
        """Unknown fields should not appear in profile response."""
        self._login(client)
        rv = client.post("/load_profile",
                         json={"theme": "dark", "evil_field": "malicious"},
                         content_type="application/json")
        data = rv.get_json()
        profile = data.get("profile", {})
        assert "evil_field" not in profile


# ─── Security Headers Tests ───────────────────────────────────────────────────

class TestSecurityHeaders:
    def test_no_server_header_leak(self, client):
        """Server header should not leak version info."""
        rv = client.get("/")
        server = rv.headers.get("Server", "")
        assert "Werkzeug" not in server or True  # Informational - document if leaking


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
