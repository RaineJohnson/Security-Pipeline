#!/usr/bin/env bash
# =============================================================================
# scan-local.sh — Run the full security pipeline locally
# =============================================================================
# Runs the same checks as CI without needing GitHub Actions. Useful for
# scanning before pushing, auditing repos that don't have the pipeline
# set up, or running against a specific directory.
#
# Usage:
#   ./scripts/scan-local.sh                     # Scan current directory
#   ./scripts/scan-local.sh /path/to/project    # Scan a specific path
#   ./scripts/scan-local.sh --secrets-only      # Only run secret detection
#   ./scripts/scan-local.sh --sast-only         # Only run SAST
#   ./scripts/scan-local.sh --deps-only         # Only run dependency scan
#
# Prerequisites:
#   brew install gitleaks semgrep          (macOS)
#   pip install semgrep && apt install gitleaks  (Linux)
# =============================================================================

set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# --- Config ---
SCAN_DIR="${1:-.}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES_DIR="${SCRIPT_DIR}/rules"
GITLEAKS_CONFIG="${SCRIPT_DIR}/.gitleaks.toml"
RESULTS_DIR="${SCRIPT_DIR}/.scan-results"

RUN_SECRETS=true
RUN_SAST=true
RUN_DEPS=true
TOTAL_FINDINGS=0

# Parse flags
for arg in "$@"; do
  case $arg in
    --secrets-only) RUN_SAST=false; RUN_DEPS=false ;;
    --sast-only) RUN_SECRETS=false; RUN_DEPS=false ;;
    --deps-only) RUN_SECRETS=false; RUN_SAST=false ;;
  esac
done

mkdir -p "$RESULTS_DIR"

echo -e "${BOLD}=========================================${NC}"
echo -e "${BOLD} Security Pipeline — Local Scan${NC}"
echo -e "${BOLD}=========================================${NC}"
echo -e " Target:  ${BLUE}${SCAN_DIR}${NC}"
echo -e " Date:    $(date)"
echo ""

# =============================================================================
# Check: Required tools installed
# =============================================================================
check_tool() {
  if ! command -v "$1" &>/dev/null; then
    echo -e "${RED}ERROR: $1 is not installed.${NC}"
    echo "  Install: $2"
    exit 1
  fi
}

if $RUN_SECRETS; then check_tool "gitleaks" "brew install gitleaks / apt install gitleaks"; fi
if $RUN_SAST; then check_tool "semgrep" "pip install semgrep / brew install semgrep"; fi

# =============================================================================
# Scan 1: Secret Detection
# =============================================================================
if $RUN_SECRETS; then
  echo -e "${BOLD}--- Secret Detection (Gitleaks) ---${NC}"

  GITLEAKS_ARGS="--source=${SCAN_DIR} --report-format=json --report-path=${RESULTS_DIR}/gitleaks.json --no-banner"
  if [ -f "$GITLEAKS_CONFIG" ]; then
    GITLEAKS_ARGS="$GITLEAKS_ARGS --config=${GITLEAKS_CONFIG}"
  fi

  if gitleaks detect $GITLEAKS_ARGS 2>/dev/null; then
    echo -e "  ${GREEN}[PASS]${NC} No secrets detected"
  else
    LEAK_COUNT=$(jq '. | length' "${RESULTS_DIR}/gitleaks.json" 2>/dev/null || echo "?")
    echo -e "  ${RED}[FAIL]${NC} Found ${LEAK_COUNT} potential secret(s)"
    echo ""
    # Show summary of findings
    jq -r '.[] | "  \(.RuleID): \(.File):\(.StartLine) — \(.Description)"' \
      "${RESULTS_DIR}/gitleaks.json" 2>/dev/null | head -20
    TOTAL_FINDINGS=$((TOTAL_FINDINGS + LEAK_COUNT))
  fi
  echo ""
fi

# =============================================================================
# Scan 2: Static Analysis (SAST)
# =============================================================================
if $RUN_SAST; then
  echo -e "${BOLD}--- Static Analysis (Semgrep) ---${NC}"

  SEMGREP_ARGS="--config=p/security-audit --config=p/secrets --metrics=off --quiet"

  # Add custom rules if available
  if [ -d "$RULES_DIR" ]; then
    SEMGREP_ARGS="$SEMGREP_ARGS --config=${RULES_DIR}/"
  fi

  SEMGREP_OUTPUT="${RESULTS_DIR}/semgrep.json"

  if semgrep $SEMGREP_ARGS --json --output="$SEMGREP_OUTPUT" "$SCAN_DIR" 2>/dev/null; then
    FINDING_COUNT=$(jq '.results | length' "$SEMGREP_OUTPUT" 2>/dev/null || echo 0)
    if [ "$FINDING_COUNT" -eq 0 ]; then
      echo -e "  ${GREEN}[PASS]${NC} No security findings"
    else
      echo -e "  ${YELLOW}[WARN]${NC} Found ${FINDING_COUNT} finding(s)"
    fi
  else
    FINDING_COUNT=$(jq '.results | length' "$SEMGREP_OUTPUT" 2>/dev/null || echo "?")
    echo -e "  ${RED}[FAIL]${NC} Found ${FINDING_COUNT} finding(s) (includes ERROR severity)"
    TOTAL_FINDINGS=$((TOTAL_FINDINGS + FINDING_COUNT))
  fi

  # Show findings breakdown by severity
  if [ -f "$SEMGREP_OUTPUT" ]; then
    ERRORS=$(jq '[.results[] | select(.extra.severity == "ERROR")] | length' "$SEMGREP_OUTPUT" 2>/dev/null || echo 0)
    WARNINGS=$(jq '[.results[] | select(.extra.severity == "WARNING")] | length' "$SEMGREP_OUTPUT" 2>/dev/null || echo 0)
    INFOS=$(jq '[.results[] | select(.extra.severity == "INFO")] | length' "$SEMGREP_OUTPUT" 2>/dev/null || echo 0)
    echo -e "  Breakdown: ${RED}${ERRORS} error${NC} / ${YELLOW}${WARNINGS} warning${NC} / ${BLUE}${INFOS} info${NC}"

    # Show top findings
    if [ "$FINDING_COUNT" -gt 0 ] 2>/dev/null; then
      echo ""
      jq -r '.results[:10][] | "  \(.extra.severity): \(.path):\(.start.line) — \(.check_id)"' \
        "$SEMGREP_OUTPUT" 2>/dev/null
      if [ "$FINDING_COUNT" -gt 10 ] 2>/dev/null; then
        echo "  ... and $((FINDING_COUNT - 10)) more (see ${SEMGREP_OUTPUT})"
      fi
    fi
  fi
  echo ""
fi

# =============================================================================
# Scan 3: Dependency Vulnerability Check
# =============================================================================
if $RUN_DEPS; then
  echo -e "${BOLD}--- Dependency Scan ---${NC}"

  DEP_FINDINGS=0

  # Node.js (npm audit)
  if [ -f "${SCAN_DIR}/package-lock.json" ]; then
    echo -e "  Scanning Node.js dependencies (npm audit)..."
    cd "$SCAN_DIR"
    if npm audit --audit-level=high --json > "${RESULTS_DIR}/npm-audit.json" 2>/dev/null; then
      echo -e "  ${GREEN}[PASS]${NC} No high/critical npm vulnerabilities"
    else
      VULN_COUNT=$(jq '.metadata.vulnerabilities.high + .metadata.vulnerabilities.critical' \
        "${RESULTS_DIR}/npm-audit.json" 2>/dev/null || echo "?")
      echo -e "  ${RED}[FAIL]${NC} Found ${VULN_COUNT} high/critical npm vulnerabilities"
      DEP_FINDINGS=$((DEP_FINDINGS + VULN_COUNT))
    fi
    cd - >/dev/null
  fi

  # Python (pip-audit)
  if [ -f "${SCAN_DIR}/requirements.txt" ]; then
    if command -v pip-audit &>/dev/null; then
      echo -e "  Scanning Python dependencies (pip-audit)..."
      if pip-audit -r "${SCAN_DIR}/requirements.txt" --format json \
        --output "${RESULTS_DIR}/pip-audit.json" 2>/dev/null; then
        echo -e "  ${GREEN}[PASS]${NC} No known Python vulnerabilities"
      else
        VULN_COUNT=$(jq '. | length' "${RESULTS_DIR}/pip-audit.json" 2>/dev/null || echo "?")
        echo -e "  ${RED}[FAIL]${NC} Found ${VULN_COUNT} vulnerable Python packages"
        DEP_FINDINGS=$((DEP_FINDINGS + VULN_COUNT))
      fi
    else
      echo -e "  ${YELLOW}[SKIP]${NC} pip-audit not installed (pip install pip-audit)"
    fi
  fi

  if [ "$DEP_FINDINGS" -eq 0 ] && [ ! -f "${SCAN_DIR}/package-lock.json" ] && [ ! -f "${SCAN_DIR}/requirements.txt" ]; then
    echo -e "  ${YELLOW}[SKIP]${NC} No package manifests found (package-lock.json, requirements.txt)"
  fi

  TOTAL_FINDINGS=$((TOTAL_FINDINGS + DEP_FINDINGS))
  echo ""
fi

# =============================================================================
# Summary
# =============================================================================
echo -e "${BOLD}=========================================${NC}"
if [ "$TOTAL_FINDINGS" -gt 0 ]; then
  echo -e "${BOLD} Result: ${RED}${TOTAL_FINDINGS} finding(s) require attention${NC}"
  echo -e "${BOLD} Details: ${NC}${RESULTS_DIR}/"
  echo -e "${BOLD}=========================================${NC}"
  exit 1
else
  echo -e "${BOLD} Result: ${GREEN}All scans passed${NC}"
  echo -e "${BOLD}=========================================${NC}"
  exit 0
fi
