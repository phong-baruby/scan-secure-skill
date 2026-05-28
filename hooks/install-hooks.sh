#!/usr/bin/env bash
# =============================================================================
# install-hooks.sh — Install git hooks for all devs on the team
# Run once after cloning: ./hooks/install-hooks.sh
# =============================================================================

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOKS_SRC="$(cd "$(dirname "$0")" && pwd)"
HOOKS_DST="$REPO_ROOT/.git/hooks"

echo "Installing security hooks..."

INSTALLED=0
SKIPPED=0

install_hook() {
  local name="$1"
  local src="$HOOKS_SRC/$name"
  local dst="$HOOKS_DST/$name"

  if [[ ! -f "$src" ]]; then
    echo "  SKIP: $src not found"
    return
  fi

  # Backup existing hook
  if [[ -f "$dst" ]] && ! grep -q "security-scan" "$dst" 2>/dev/null; then
    cp "$dst" "${dst}.backup-$(date +%Y%m%d)"
    echo "  Backed up existing $name → ${dst}.backup"
  fi

  cp "$src" "$dst"
  chmod +x "$dst"
  echo "  ✓ Installed: $name"
  INSTALLED=$((INSTALLED + 1))
}

install_hook "pre-commit"

echo ""
echo "Done. $INSTALLED hook(s) installed."
echo ""

# ── Check tools ───────────────────────────────────────────────────────────────
echo "Checking required tools..."
MISSING=()

command -v gitleaks &>/dev/null && echo "  ✓ gitleaks" || MISSING+=("gitleaks")
command -v semgrep  &>/dev/null && echo "  ✓ semgrep"  || MISSING+=("semgrep")
command -v trivy    &>/dev/null && echo "  ✓ trivy"    || MISSING+=("trivy")

if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo ""
  echo "Missing tools: ${MISSING[*]}"
  echo "Install on macOS:"
  for tool in "${MISSING[@]}"; do
    case $tool in
      gitleaks) echo "  brew install gitleaks" ;;
      semgrep)  echo "  pip install semgrep" ;;
      trivy)    echo "  brew install trivy" ;;
    esac
  done
fi
