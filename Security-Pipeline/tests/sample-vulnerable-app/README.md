# Sample Vulnerable Application

> **This directory contains intentionally vulnerable code for testing the security pipeline. DO NOT use any of this code in production.**

These files exist to demonstrate that the pipeline's scanners work correctly. Each file contains labeled vulnerabilities with CWE references, the scanner that catches them, and the fix.

## What's Here

| File | Vulnerabilities Demonstrated | Scanner |
|------|------------------------------|---------|
| `app.py` | Hardcoded creds, SQL injection, command injection, weak crypto, debug mode, wildcard CORS | Semgrep, Gitleaks |
| `server.js` | Same categories in Node.js — plus XSS, error info leakage | Semgrep, Gitleaks |
| `Dockerfile` | Latest tag, no USER, secrets in ENV, ADD vs COPY | Hadolint, Trivy, Semgrep |
| `main.tf` | Public S3, open security groups, unencrypted RDS, wildcard IAM, hardcoded passwords | Checkov, tfsec |
| `requirements.txt` | Python packages with known CVEs (Flask, requests, urllib3, certifi) | pip-audit, OWASP Dependency-Check |
| `package.json` | Node packages with known CVEs (express, lodash, axios, jsonwebtoken) | npm audit, OWASP Dependency-Check |

## Running the Scanners Against This Directory

```bash
# Semgrep (catches code-level vulnerabilities)
semgrep --config=p/security-audit --config=../rules/ .

# Gitleaks (catches hardcoded secrets)
gitleaks detect --source=. --no-git

# pip-audit (catches vulnerable Python packages)
pip-audit -r requirements.txt

# Checkov (catches Terraform misconfigurations)
checkov -d . --framework terraform

# Hadolint (catches Dockerfile issues)
hadolint Dockerfile
```

Each command above should produce findings — that's the point.
