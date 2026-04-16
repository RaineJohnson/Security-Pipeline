"""
=============================================================================
SAMPLE VULNERABLE APPLICATION — FOR TESTING ONLY
=============================================================================
This file contains INTENTIONAL security vulnerabilities to demonstrate
what the security pipeline catches. Every issue here is flagged by at
least one scanner in the pipeline.

DO NOT use any of this code in production.

Each vulnerability is labeled with:
  - The CWE (Common Weakness Enumeration) it maps to
  - Which scanner catches it (Semgrep, Gitleaks, or Dependency-Check)
  - The fix that would resolve it
=============================================================================
"""

import os
import hashlib
import random
import sqlite3
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)

# =============================================================================
# VULN 1: Hardcoded credentials
# CWE-798 | Caught by: Semgrep (hardcoded-password-assignment), Gitleaks
# Fix: Use environment variables — os.environ.get('DB_PASSWORD')
# =============================================================================
DB_PASSWORD = "supersecretpassword123"
API_SECRET = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
JWT_SECRET = "my-jwt-secret-key-do-not-share"

# =============================================================================
# VULN 2: Hardcoded database connection string
# CWE-798 | Caught by: Semgrep (hardcoded-connection-string), Gitleaks
# Fix: DATABASE_URL = os.environ.get('DATABASE_URL')
# =============================================================================
DATABASE_URL = "postgresql://admin:p4ssw0rd@prod-db.internal:5432/customers"


# =============================================================================
# VULN 3: SQL Injection via string concatenation
# CWE-89 | Caught by: Semgrep (sql-string-concatenation)
# Fix: Use parameterized queries — cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
# =============================================================================
@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)  # SQL INJECTION
    result = cursor.fetchone()
    conn.close()
    return jsonify(result)


# =============================================================================
# VULN 4: OS Command Injection via f-string
# CWE-78 | Caught by: Semgrep (shell-injection-via-format)
# Fix: subprocess.run(["ping", "-c", "1", host], capture_output=True)
# =============================================================================
@app.route("/ping")
def ping_host():
    host = request.args.get("host")
    result = os.system(f"ping -c 1 {host}")  # COMMAND INJECTION
    return jsonify({"exit_code": result})


# =============================================================================
# VULN 5: Weak hash algorithm (MD5)
# CWE-328 | Caught by: Semgrep (weak-hash-algorithm)
# Fix: hashlib.sha256(data).hexdigest()
# =============================================================================
def hash_data(data):
    return hashlib.md5(data.encode()).hexdigest()  # WEAK HASH


# =============================================================================
# VULN 6: Insecure random for security-sensitive operation
# CWE-338 | Caught by: Semgrep (insecure-random-for-security)
# Fix: import secrets; secrets.token_hex(32)
# =============================================================================
def generate_session_token():
    return str(random.random())  # NOT CRYPTOGRAPHICALLY SECURE


def generate_otp():
    return random.randint(100000, 999999)  # NOT CRYPTOGRAPHICALLY SECURE


# =============================================================================
# VULN 7: Flask debug mode in production
# CWE-489 | Caught by: Semgrep (flask-debug-enabled)
# Fix: app.run(debug=os.environ.get('FLASK_DEBUG', False))
# =============================================================================
# VULN 8: Wildcard CORS
# CWE-942 | Caught by: Semgrep (cors-wildcard)
# Fix: Restrict to specific trusted origins
# =============================================================================
@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"  # WILDCARD CORS
    return response


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)  # DEBUG MODE
