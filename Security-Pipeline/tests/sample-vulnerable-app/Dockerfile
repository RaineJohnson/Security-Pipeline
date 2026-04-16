# ===========================================================================
# SAMPLE VULNERABLE DOCKERFILE — FOR TESTING ONLY
# ===========================================================================
# Contains intentional misconfigurations to demonstrate what Hadolint,
# Trivy, and the infrastructure Semgrep rules catch.
#
# DO NOT use this Dockerfile in production.
# ===========================================================================

# VULN 1: Using :latest tag — non-reproducible builds
# Caught by: Semgrep (dockerfile-latest-tag), Hadolint (DL3007)
# Fix: FROM python:3.12-slim
FROM python:latest

# VULN 2: Running apt-get without version pinning
# Caught by: Hadolint (DL3008)
# Fix: apt-get install -y --no-install-recommends curl=7.88.1-10
RUN apt-get update && apt-get install -y curl wget netcat-openbsd

# VULN 3: Using ADD instead of COPY for local files
# Caught by: Semgrep (dockerfile-add-instead-of-copy), Hadolint (DL3020)
# Fix: COPY requirements.txt .
ADD requirements.txt .

RUN pip install -r requirements.txt

# VULN 4: Storing secrets in ENV
# Caught by: Hadolint (DL3059 suggestion), Gitleaks, Semgrep
# Fix: Use runtime environment variables or secrets managers
ENV DATABASE_PASSWORD=pr0duction_p4ss
ENV API_KEY=sk_live_fake_key_for_demo

ADD . /app
WORKDIR /app

EXPOSE 5000

# VULN 5: No USER directive — container runs as root
# Caught by: Semgrep (dockerfile-run-as-root), Hadolint, Trivy config scan
# Fix: RUN adduser --disabled-password --gecos '' appuser && USER appuser
CMD ["python", "app.py"]
