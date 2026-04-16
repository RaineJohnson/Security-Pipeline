# Security Scanning Pipeline

A complete DevSecOps pipeline built with GitHub Actions. Integrates secret detection, static analysis, dependency scanning, container image scanning, and infrastructure-as-code policy checks into the CI/CD workflow. Includes custom Semgrep rules, pre-commit hooks for local scanning, and a sample vulnerable application that demonstrates every scanner catching real issues.

## What This Pipeline Catches

| Layer | Scanner | What It Finds |
|-------|---------|---------------|
| **Secrets** | Gitleaks | Leaked API keys, passwords, tokens, private keys, connection strings in commit history |
| **Code (SAST)** | Semgrep | SQL injection, command injection, XSS, hardcoded creds, weak crypto, insecure defaults |
| **Dependencies** | OWASP Dependency-Check, npm audit, pip-audit | Known CVEs in third-party packages (NVD/OSV databases) |
| **Containers** | Trivy, Hadolint | OS package vulnerabilities in images, Dockerfile misconfigurations, running as root |
| **Infrastructure** | Checkov, tfsec | Terraform/CloudFormation misconfigs — public S3, open security groups, unencrypted storage, wildcard IAM |

## Pipeline Architecture

```
  Push / PR
      │
      ├─── security-scan.yml ─────────────────────────────────────────────┐
      │       ├── Secret Detection (Gitleaks)                             │
      │       │     └── Full commit history + custom .gitleaks.toml       │
      │       ├── Dependency Scan (OWASP + npm audit + pip-audit)         │
      │       │     └── CVE lookup against NVD/OSV                        │
      │       ├── SAST (Semgrep)                                          │
      │       │     └── Community rules + 15 custom rules in rules/       │
      │       └── Pipeline Summary                                        │
      │                                                                   │
      ├─── container-scan.yml (on Dockerfile changes) ─────────────────┐  │
      │       ├── Dockerfile Lint (Hadolint)                           │  │
      │       ├── Image Vulnerability Scan (Trivy)                     │  │
      │       └── Image Configuration Audit (Trivy config)             │  │
      │                                                                │  │
      ├─── iac-scan.yml (on .tf / k8s changes) ───────────────────┐    │  │
      │       ├── IaC Policy Scan (Checkov)                        │   │  │
      │       ├── Terraform Security (tfsec)                       │   │  │
      │       └── Terraform Validate + Format Check                │   │  │
      │                                                            │   │  │
      │         All findings ──────────────────────────────────────────┘  │
      │                        │                                          │
      │                        ▼                                          │
      │              GitHub Security Tab (SARIF)                          │
      └───────────────────────────────────────────────────────────────────┘

  Local Development
      │
      ├── pre-commit hooks (Gitleaks + Semgrep — runs on every commit)
      └── scripts/scan-local.sh (full pipeline on your machine)
```

## Quick Start

### 1. Add the pipeline to any existing repo

Copy the workflow files and configurations into your project:

```bash
# Clone this repo
git clone https://github.com/RaineJohnson/Security-Pipeline.git

# Copy workflows into your project
cp -r Security-Pipeline/.github/workflows/ your-project/.github/workflows/
cp Security-Pipeline/.gitleaks.toml your-project/
cp -r Security-Pipeline/rules/ your-project/rules/

# (Optional) Set up pre-commit hooks for local scanning
cp Security-Pipeline/.pre-commit-config.yaml your-project/
cd your-project && pip install pre-commit && pre-commit install
```

### 2. No secrets or API keys required

Every tool in this pipeline is open source and runs without API keys. Semgrep uses offline rulesets. Gitleaks uses the built-in + custom patterns. OWASP Dependency-Check downloads the NVD database at runtime.

### 3. View results

After a pipeline run, findings appear in three places:

- **Actions tab** → Pass/fail status per job, with human-readable summaries
- **Security tab** → SARIF-formatted findings with severity, file location, line number, and remediation guidance
- **PR comments** → Scan summaries posted directly on pull requests

### 4. Run locally

```bash
# Full pipeline on your machine (same checks as CI)
./scripts/scan-local.sh

# Scan a specific project
./scripts/scan-local.sh /path/to/project

# Run only specific scanners
./scripts/scan-local.sh --secrets-only
./scripts/scan-local.sh --sast-only
./scripts/scan-local.sh --deps-only
```

## Repository Structure

```
├── README.md
├── .gitignore
├── .gitleaks.toml                           # Gitleaks config — custom patterns + allowlist
├── .pre-commit-config.yaml                  # Pre-commit hooks for local scanning
│
├── .github/workflows/
│   ├── security-scan.yml                    # Core pipeline: secrets + SAST + dependency scan
│   ├── container-scan.yml                   # Dockerfile lint + Trivy image scan + config audit
│   └── iac-scan.yml                         # Checkov + tfsec + Terraform validate
│
├── rules/
│   ├── custom-security-rules.yml            # 12 custom Semgrep rules for code security
│   └── infrastructure-rules.yml             # 5 custom Semgrep rules for Dockerfiles + K8s
│
├── scripts/
│   └── scan-local.sh                        # Run the full pipeline locally (no CI needed)
│
└── tests/
    └── sample-vulnerable-app/
        ├── README.md                        # What each vulnerability demonstrates
        ├── app.py                           # Python app — 8 labeled vulnerabilities
        ├── server.js                        # Node.js app — 9 labeled vulnerabilities
        ├── Dockerfile                       # 5 Dockerfile misconfigurations
        ├── main.tf                          # 10 Terraform misconfigurations
        ├── requirements.txt                 # Python packages with known CVEs
        └── package.json                     # Node packages with known CVEs
```

## Custom Rules

This pipeline extends community rulesets with 17 custom Semgrep rules covering patterns the defaults miss.

### Code Security Rules (`rules/custom-security-rules.yml`)

| Rule ID | Severity | What It Catches |
|---------|----------|-----------------|
| `hardcoded-password-assignment` | ERROR | Variables named `password`, `secret`, `api_key` assigned string literals |
| `hardcoded-connection-string` | ERROR | Database URLs with embedded credentials (`postgres://user:pass@host`) |
| `weak-hash-algorithm` | WARNING | MD5 or SHA-1 used for hashing (Python `hashlib` + Node `crypto`) |
| `insecure-random-for-security` | WARNING | `random.random()` or `Math.random()` for tokens/OTPs |
| `ecb-mode-encryption` | ERROR | AES in ECB mode (no semantic security) |
| `shell-injection-via-format` | ERROR | User input in `os.system()`, `subprocess.call()` via f-strings |
| `sql-string-concatenation` | ERROR | SQL queries built with `+` or f-strings instead of parameterized queries |
| `flask-debug-enabled` | ERROR | `app.run(debug=True)` in Flask |
| `cors-wildcard` | WARNING | `Access-Control-Allow-Origin: *` |
| `missing-csrf-protection-express` | WARNING | Express POST routes without CSRF middleware |

### Infrastructure Rules (`rules/infrastructure-rules.yml`)

| Rule ID | Severity | What It Catches |
|---------|----------|-----------------|
| `dockerfile-run-as-root` | WARNING | Dockerfile without a USER directive |
| `dockerfile-latest-tag` | WARNING | `FROM image:latest` — non-reproducible builds |
| `dockerfile-add-instead-of-copy` | INFO | ADD used where COPY would be safer |
| `k8s-privileged-container` | ERROR | `privileged: true` in Kubernetes securityContext |
| `k8s-host-network` | WARNING | `hostNetwork: true` bypasses network policies |

## Workflows in Detail

### `security-scan.yml` — Core Application Security

Triggers on every push to `main`/`develop` and every PR. Also runs weekly on a schedule to catch newly disclosed CVEs in existing dependencies.

**Jobs:**
1. **Secret Detection** — Gitleaks with full commit history scan and custom patterns from `.gitleaks.toml`
2. **Dependency Scan** — Auto-detects language (Node.js via `package-lock.json`, Python via `requirements.txt`), runs the appropriate package auditor, then runs OWASP Dependency-Check as a language-agnostic backstop
3. **SAST** — Semgrep with `p/security-audit` + `p/secrets` + `p/owasp-top-ten` + custom rules from `rules/`
4. **Pipeline Summary** — Aggregates pass/fail status from all jobs and fails the pipeline if any scan found issues

### `container-scan.yml` — Container Security

Triggers only when Dockerfiles or docker-compose files change (path filtering to avoid unnecessary runs).

**Jobs:**
1. **Dockerfile Lint** — Hadolint catches best-practice violations before the image is built
2. **Image Vulnerability Scan** — Builds the image, then scans it with Trivy for OS package and library CVEs. Fails on HIGH/CRITICAL, ignores unfixed vulnerabilities
3. **Image Configuration Audit** — Checks for runtime security issues (running as root, exposed ports, missing health checks)

### `iac-scan.yml` — Infrastructure-as-Code Security

Triggers only when Terraform files, CloudFormation templates, or Kubernetes manifests change.

**Jobs:**
1. **Checkov** — Policy-as-code scanning across Terraform, CloudFormation, Kubernetes, and Dockerfiles against 1000+ built-in policies
2. **tfsec** — Terraform-specific deep analysis (runs only if `.tf` files exist)
3. **Terraform Validate** — Syntax validation and format checking (`terraform fmt -check`)

## Gitleaks Configuration

The `.gitleaks.toml` file extends Gitleaks' default ruleset with patterns for:

- Database connection strings with embedded credentials
- Private keys pasted into source code
- JWT secrets in config files
- SendGrid and Twilio API keys
- Internal/private IP addresses (potential network topology leakage)

It also defines an **allowlist** that excludes test fixtures, the sample vulnerable app directory, and known false-positive patterns (`placeholder`, `changeme`, `your-key-here`).

## Pre-Commit Hooks

The `.pre-commit-config.yaml` runs a subset of the pipeline on every local commit:

```bash
# One-time setup
pip install pre-commit
pre-commit install

# Now every git commit automatically runs:
#   - Gitleaks (secret detection)
#   - Semgrep (SAST with custom rules)
#   - Hadolint (Dockerfile linting)
#   - AWS credential detection
#   - Private key detection
#   - Branch protection (blocks direct commits to main)
```

This catches issues before they ever reach the remote repo. The CI pipeline serves as a safety net for cases where pre-commit is bypassed (e.g., `--no-verify` or contributors without hooks installed).

## Sample Vulnerable Application

The `tests/sample-vulnerable-app/` directory contains intentionally vulnerable code across 6 files covering Python, Node.js, Dockerfiles, Terraform, and dependency manifests. Each vulnerability is labeled with:

- The CWE number it maps to
- Which scanner catches it
- The specific fix that resolves it

To see the scanners in action:

```bash
# Run Semgrep against the sample app
semgrep --config=p/security-audit --config=./rules/ tests/sample-vulnerable-app/

# Run Gitleaks
gitleaks detect --source=tests/sample-vulnerable-app/ --no-git

# Run Checkov against the Terraform file
checkov -f tests/sample-vulnerable-app/main.tf

# Run Hadolint against the Dockerfile
hadolint tests/sample-vulnerable-app/Dockerfile
```

## Customization

### Adding the pipeline to a new language/stack

The pipeline auto-detects languages by checking for manifest files. To add support for a new stack:

1. Add a detection condition in `security-scan.yml` (check for `Gemfile.lock`, `go.sum`, `pom.xml`, etc.)
2. Add the appropriate audit tool (e.g., `bundler-audit` for Ruby, `govulncheck` for Go)
3. Add language-specific Semgrep rules: `--config=p/ruby` or `--config=p/golang`

### Adjusting severity thresholds

By default, the pipeline fails on ERROR severity findings. To also fail on warnings:

```yaml
# In security-scan.yml, Semgrep step:
--severity WARNING    # Fail on WARNING and above (stricter)
--severity ERROR      # Fail on ERROR only (default)
```

### Skipping specific rules

For Checkov:
```yaml
skip_check: CKV_AWS_18,CKV_AWS_21    # Skip specific checks by ID
```

For Semgrep, add to the command:
```yaml
--exclude-rule hardcoded-password-assignment    # Skip specific rule
--exclude='vendor/*'                            # Skip paths
```

## Design Decisions

**Why multiple scanners instead of one tool?**
No single scanner catches everything. Gitleaks is purpose-built for credential detection across git history — Semgrep doesn't do this. Semgrep catches code-level patterns that dependency scanners can't see. Trivy understands container image layer composition. Checkov speaks Terraform/CloudFormation natively. Layering them provides defense in depth.

**Why SARIF output?**
SARIF (Static Analysis Results Interchange Format) is the standard that GitHub's Security tab consumes. Uploading SARIF means findings appear in a unified dashboard with deduplication, severity filtering, and tracking over time — regardless of which scanner produced them.

**Why custom rules on top of community rulesets?**
Community rules are broad. Custom rules catch patterns specific to your stack and team conventions. The `hardcoded-connection-string` rule, for example, catches `postgres://user:pass@host` patterns that the generic `p/secrets` ruleset sometimes misses when they're in config files rather than `.env`.

**Why pre-commit hooks AND CI?**
Pre-commit hooks catch issues instantly during development. CI is the safety net that catches everything pre-commit misses (contributors without hooks, `--no-verify` usage, dependency CVEs that emerge after the code was written). Both layers are needed.

**Why path filtering on container and IaC workflows?**
Running Trivy image builds or Terraform validation on every push wastes CI minutes when no infrastructure files changed. Path filtering ensures these workflows only trigger when relevant files are modified, keeping feedback loops fast for application-only changes.

## Technologies

![GitHub Actions](https://img.shields.io/badge/-GitHub%20Actions-2088FF?style=flat&logo=githubactions&logoColor=white)
![Semgrep](https://img.shields.io/badge/-Semgrep-3DA639?style=flat)
![Gitleaks](https://img.shields.io/badge/-Gitleaks-333333?style=flat)
![Trivy](https://img.shields.io/badge/-Trivy-1904DA?style=flat)
![Checkov](https://img.shields.io/badge/-Checkov-7B42BC?style=flat)
![Hadolint](https://img.shields.io/badge/-Hadolint-333333?style=flat)
![OWASP](https://img.shields.io/badge/-OWASP-000000?style=flat&logo=owasp&logoColor=white)
![Terraform](https://img.shields.io/badge/-Terraform-7B42BC?style=flat&logo=terraform&logoColor=white)
![Docker](https://img.shields.io/badge/-Docker-2496ED?style=flat&logo=docker&logoColor=white)
![Pre--commit](https://img.shields.io/badge/-pre--commit-FAB040?style=flat&logo=precommit&logoColor=black)
