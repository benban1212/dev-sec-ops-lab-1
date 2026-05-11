"""
DevSecOps Lab - Session 3
Security Monitoring & Incident Response Middleware
Demonstrates: WAF-like request inspection, rate limiting, alerting
"""

from flask import Flask, request, jsonify, g
from functools import wraps
import time
import hashlib
import re
import logging
import json
from collections import defaultdict
from datetime import datetime
import threading

# ─── Security Monitoring Setup ────────────────────────────────────────────────

# Structured JSON logging for SIEM integration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("security_monitor")

class SecurityEvent:
    """Structured security event for SIEM consumption."""
    def __init__(self, event_type, severity, details, ip=None):
        self.timestamp = datetime.utcnow().isoformat() + "Z"
        self.event_type = event_type
        self.severity = severity
        self.details = details
        self.ip = ip or "unknown"
        self.request_id = hashlib.sha256(
            f"{self.timestamp}{self.ip}".encode()
        ).hexdigest()[:12]

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "request_id": self.request_id,
            "event_type": self.event_type,
            "severity": self.severity,
            "source_ip": self.ip,
            "details": self.details
        }

    def log(self):
        logger.warning(json.dumps(self.to_dict()))


# ─── Rate Limiter ─────────────────────────────────────────────────────────────

class RateLimiter:
    """Token bucket rate limiter per IP."""
    def __init__(self, max_requests=10, window_seconds=60):
        self.max_requests = max_requests
        self.window = window_seconds
        self._buckets = defaultdict(list)
        self._lock = threading.Lock()

    def is_allowed(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            bucket = self._buckets[ip]
            # Remove old entries outside window
            self._buckets[ip] = [t for t in bucket if now - t < self.window]
            if len(self._buckets[ip]) >= self.max_requests:
                return False
            self._buckets[ip].append(now)
            return True

    def get_count(self, ip: str) -> int:
        now = time.time()
        with self._lock:
            return len([t for t in self._buckets[ip] if now - t < self.window])


# ─── WAF Patterns ─────────────────────────────────────────────────────────────

WAF_RULES = [
    {
        "id": "WAF-001",
        "name": "SQL Injection",
        "pattern": re.compile(
            r"(\bSELECT\b|\bUNION\b|\bINSERT\b|\bDROP\b|\bDELETE\b|"
            r"'--|\bOR\b\s+['\"0-9]|\bAND\b\s+['\"0-9])",
            re.IGNORECASE
        ),
        "severity": "HIGH"
    },
    {
        "id": "WAF-002",
        "name": "XSS",
        "pattern": re.compile(
            r"(<script|javascript:|on\w+\s*=|<iframe|<object|<embed)",
            re.IGNORECASE
        ),
        "severity": "HIGH"
    },
    {
        "id": "WAF-003",
        "name": "Path Traversal",
        "pattern": re.compile(r"\.\./|\.\.\\|%2e%2e", re.IGNORECASE),
        "severity": "HIGH"
    },
    {
        "id": "WAF-004",
        "name": "Command Injection",
        "pattern": re.compile(r"[;&|`$()]\s*(ls|cat|id|whoami|pwd|wget|curl|bash|sh)\b"),
        "severity": "CRITICAL"
    },
    {
        "id": "WAF-005",
        "name": "SSRF Attempt",
        "pattern": re.compile(r"(169\.254\.|127\.|10\.|192\.168\.|file://|gopher://)", re.IGNORECASE),
        "severity": "HIGH"
    },
]


def inspect_request(req) -> list:
    """Inspect all request parameters against WAF rules."""
    findings = []
    
    # Collect all input
    inputs = []
    inputs.extend(req.args.values())
    inputs.extend(req.form.values())
    if req.is_json:
        def flatten(obj, prefix=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    flatten(v, f"{prefix}.{k}")
            elif isinstance(obj, list):
                for item in obj:
                    flatten(item, prefix)
            else:
                inputs.append(str(obj))
        try:
            flatten(req.get_json())
        except Exception:
            pass

    for rule in WAF_RULES:
        for value in inputs:
            if rule["pattern"].search(value):
                findings.append({
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "matched_value": value[:100]  # Truncate for logs
                })
                break  # One finding per rule

    return findings


# ─── Security Middleware ───────────────────────────────────────────────────────

def create_monitored_app():
    app = Flask(__name__)
    rate_limiter = RateLimiter(max_requests=30, window_seconds=60)
    login_limiter = RateLimiter(max_requests=5, window_seconds=300)  # Stricter for login

    @app.before_request
    def security_middleware():
        ip = request.remote_addr or "unknown"
        path = request.path

        # 1. Rate limiting (global)
        if not rate_limiter.is_allowed(ip):
            SecurityEvent(
                "RATE_LIMIT_EXCEEDED", "MEDIUM",
                {"path": path, "count": rate_limiter.get_count(ip)}, ip
            ).log()
            return jsonify({"error": "Too many requests"}), 429

        # 2. Stricter rate limiting for auth endpoints
        if path in ["/login", "/api/token"] and request.method == "POST":
            if not login_limiter.is_allowed(ip):
                SecurityEvent(
                    "BRUTE_FORCE_DETECTED", "HIGH",
                    {"path": path, "message": "Login rate limit exceeded"}, ip
                ).log()
                return jsonify({"error": "Too many login attempts. Try again in 5 minutes."}), 429

        # 3. WAF inspection
        findings = inspect_request(request)
        if findings:
            for finding in findings:
                SecurityEvent(
                    "WAF_BLOCK",
                    finding["severity"],
                    {
                        "rule": finding["rule_id"],
                        "rule_name": finding["rule_name"],
                        "path": path,
                        "method": request.method
                    },
                    ip
                ).log()
            # Block if any HIGH/CRITICAL finding
            if any(f["severity"] in ["HIGH", "CRITICAL"] for f in findings):
                return jsonify({"error": "Request blocked by security policy"}), 400

        # 4. Security headers
        g.start_time = time.time()

    @app.after_request
    def add_security_headers(response):
        # Prevent MIME sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Prevent clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        # XSS protection
        response.headers["X-XSS-Protection"] = "1; mode=block"
        # Content Security Policy
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "frame-ancestors 'none';"
        )
        # HTTPS only (enable in prod)
        # response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        # Remove server fingerprint
        response.headers.pop("Server", None)

        # Log response time for anomaly detection
        if hasattr(g, "start_time"):
            duration_ms = (time.time() - g.start_time) * 1000
            if duration_ms > 5000:  # Slow request = potential DoS
                SecurityEvent(
                    "SLOW_REQUEST", "LOW",
                    {"path": request.path, "duration_ms": round(duration_ms, 2)},
                    request.remote_addr
                ).log()

        return response

    # ─── Demo Routes ──────────────────────────────────────────────────────────

    @app.route("/")
    def index():
        return jsonify({
            "status": "ok",
            "message": "Security monitoring active",
            "endpoints": ["/health", "/api/demo"]
        })

    @app.route("/health")
    def health():
        return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat()})

    @app.route("/api/demo")
    def demo():
        q = request.args.get("q", "hello")
        return jsonify({"echo": q, "length": len(q)})

    @app.route("/security/events")
    def security_events():
        """Demo: Return recent security event log (in prod: query SIEM)."""
        return jsonify({
            "message": "In production, query your SIEM/log aggregation tool",
            "example_event": SecurityEvent(
                "EXAMPLE", "INFO",
                {"detail": "Security monitoring is active"}
            ).to_dict()
        })

    return app


# ─── Incident Response Runbook (printed on startup) ──────────────────────────

RUNBOOK = """
╔══════════════════════════════════════════════════════════════╗
║          INCIDENT RESPONSE RUNBOOK - Quick Reference         ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  P1 - CRITICAL (Active Breach)                               ║
║    1. Isolate: Block attacker IP at load balancer            ║
║    2. Preserve: Snapshot logs to immutable storage           ║
║    3. Contain: Rotate all secrets & API keys immediately     ║
║    4. Notify: Security team + management within 15 minutes   ║
║    5. Escalate: CIRT/legal if PII or customer data affected  ║
║                                                              ║
║  P2 - HIGH (WAF/Rate Limit Triggered)                        ║
║    1. Investigate: Review security event logs                ║
║    2. Correlate: Check other IPs from same /24 subnet        ║
║    3. Decide: Temp block or permanent ban                    ║
║    4. Document: Create ticket with IOCs                      ║
║                                                              ║
║  P3 - MEDIUM (Anomalous Traffic)                             ║
║    1. Monitor: Increase logging verbosity                    ║
║    2. Analyze: Check for reconnaissance patterns             ║
║    3. Alert: Notify on-call engineer                         ║
║                                                              ║
║  Useful Commands:                                            ║
║    Block IP:  iptables -I INPUT -s <IP> -j DROP              ║
║    Log check: journalctl -u flask-app -f                     ║
║    Rotate key: export SECRET_KEY=$(python -c                 ║
║                "import secrets; print(secrets.token_hex())") ║
╚══════════════════════════════════════════════════════════════╝
"""

if __name__ == "__main__":
    print(RUNBOOK)
    monitored_app = create_monitored_app()
    print("🛡️  Security monitoring active on http://127.0.0.1:5002")
    print("   Try: curl 'http://127.0.0.1:5002/api/demo?q=<script>alert(1)</script>'")
    print("   Try: curl 'http://127.0.0.1:5002/api/demo?q=' OR 1=1--'")
    monitored_app.run(debug=False, host="127.0.0.1", port=5002)
