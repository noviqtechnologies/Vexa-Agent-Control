#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# VEXA AGENT CONTROL — UNIFIED BOOTSTRAP & REPRODUCIBILITY RUNNER (POSIX)
# ══════════════════════════════════════════════════════════════════════════════
# Validates toolchains, installs prerequisites, and runs full test suites.
# Works across Linux (Ubuntu/Debian/Arch/RHEL), macOS (ARM64/x86_64), and WSL2.
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${WORKSPACE_ROOT}"

echo "════════════════════════════════════════════════════════════════════"
echo "  Vexa Agent Control — Bootstrapping & Reproducibility Suite"
echo "════════════════════════════════════════════════════════════════════"

# 1. Check Toolchain Requirements
echo ""
echo "── 1. Validating Core Toolchains ──────────────────────────────────"

FAILED_TOOLS=0

if command -v rustc >/dev/null 2>&1; then
    echo "  [OK] rustc:    $(rustc --version)"
else
    echo "  [FAIL] rustc is not installed. Run: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    FAILED_TOOLS=$((FAILED_TOOLS + 1))
fi

if command -v cargo >/dev/null 2>&1; then
    echo "  [OK] cargo:    $(cargo --version)"
else
    echo "  [FAIL] cargo is not installed."
    FAILED_TOOLS=$((FAILED_TOOLS + 1))
fi

if command -v go >/dev/null 2>&1; then
    echo "  [OK] go:       $(go version)"
else
    echo "  [WARN] go is not installed. Skipping control-plane Go API build/vet."
fi

if command -v node >/dev/null 2>&1; then
    echo "  [OK] node:     $(node --version)"
else
    echo "  [WARN] node is not installed. Skipping control-plane UI build."
fi

if command -v npm >/dev/null 2>&1; then
    echo "  [OK] npm:      $(npm --version)"
fi

if [ ${FAILED_TOOLS} -gt 0 ]; then
    echo ""
    echo "  [ERROR] Required toolchains are missing. Please install them and re-run."
    exit 1
fi

# 2. Rust Toolchain Components & Checks
echo ""
echo "── 2. Checking Rust Formatting & Linting ───────────────────────────"
cargo fmt --check
echo "  [OK] cargo fmt check passed"

cargo clippy --all-targets -- -D warnings
echo "  [OK] cargo clippy passed with 0 warnings"

# 3. Rust Test Suite
echo ""
echo "── 3. Running Rust Unit & Integration Tests ───────────────────────"
cargo test --all-targets
echo "  [OK] cargo test suite passed"

# 4. Go Control-Plane API Validation (if Go present)
if command -v go >/dev/null 2>&1 && [ -d "control-plane/api" ]; then
    echo ""
    echo "── 4. Validating Control Plane Go API ──────────────────────────────"
    (
        cd control-plane/api
        go vet ./...
        echo "  [OK] Go vet passed on control-plane/api"
    )
fi

# 5. UI Dashboard Build (if Node & npm present)
if command -v npm >/dev/null 2>&1 && [ -d "control-plane/ui" ]; then
    echo ""
    echo "── 5. Validating Control Plane Web UI ─────────────────────────────"
    (
        cd control-plane/ui
        if [ ! -d "node_modules" ]; then
            npm ci
        fi
        npm run build
        echo "  [OK] UI TypeScript build passed"
    )
fi

echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "  Bootstrap & Validation Successful! All environments verified."
echo "════════════════════════════════════════════════════════════════════"
