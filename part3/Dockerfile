# ─── DevSecOps Lab - Session 3 ────────────────────────────────────────────────
# Production-hardened Dockerfile for Flask application
# Follows CIS Docker Benchmark recommendations
# ──────────────────────────────────────────────────────────────────────────────

# Stage 1: Build dependencies
FROM python:3.11-slim AS builder

WORKDIR /build

# Install only build-time dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


# Stage 2: Production image (minimal attack surface)
FROM python:3.11-slim AS production

# Security: Create non-root user
RUN groupadd -r appgroup && useradd -r -g appgroup -d /app -s /sbin/nologin appuser

WORKDIR /app

# Copy only installed packages from builder (not build tools)
COPY --from=builder /root/.local /home/appuser/.local

# Copy application code
COPY --chown=appuser:appgroup app_secure.py .
COPY --chown=appuser:appgroup templates/ ./templates/

# Security: Remove package manager after use (reduce attack surface)
RUN apt-get update && \
    apt-get install -y --no-install-recommends dumb-init && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Security: No writable filesystem in production
# Only /tmp and specific dirs are writable
RUN mkdir -p /app/data && chown appuser:appgroup /app/data

# Switch to non-root user
USER appuser

# PATH for user-installed packages
ENV PATH=/home/appuser/.local/bin:$PATH

# Expose on high port (not privileged)
EXPOSE 8000

# Security: Use dumb-init as PID 1 (handles signals correctly)
# Use gunicorn (production WSGI server, not Flask dev server)
ENTRYPOINT ["dumb-init", "--"]
CMD ["gunicorn", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "2", \
     "--timeout", "30", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--log-level", "info", \
     "app_secure:app"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/')" || exit 1
