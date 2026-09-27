# Vexa Agent Control - Unified Bootstrap & Reproducibility Runner (PowerShell)
# Validates toolchains, installs prerequisites, and runs full test suites on Windows.

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$WorkspaceRoot = (Resolve-Path (Join-Path $ScriptDir "..")).Path

Set-Location $WorkspaceRoot

Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "  Vexa Agent Control - Bootstrapping and Reproducibility Suite" -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan

# 1. Check Toolchain Requirements
Write-Host ""
Write-Host "-- 1. Validating Core Toolchains ----------------------------------" -ForegroundColor Yellow

$FailedTools = 0

try {
    $rustcVer = & rustc --version
    Write-Host "  [OK] rustc:    $rustcVer" -ForegroundColor Green
} catch {
    Write-Host "  [FAIL] rustc is not found. Install from https://rustup.rs" -ForegroundColor Red
    $FailedTools++
}

try {
    $cargoVer = & cargo --version
    Write-Host "  [OK] cargo:    $cargoVer" -ForegroundColor Green
} catch {
    Write-Host "  [FAIL] cargo is not found." -ForegroundColor Red
    $FailedTools++
}

$hasGo = $false
try {
    $goVer = & go version
    Write-Host "  [OK] go:       $goVer" -ForegroundColor Green
    $hasGo = $true
} catch {
    Write-Host "  [WARN] go is not installed. Skipping control-plane Go API build/vet." -ForegroundColor Yellow
}

$hasNpm = $false
try {
    $nodeVer = & node --version
    $npmVer = & npm --version
    Write-Host "  [OK] node:     $nodeVer | npm: $npmVer" -ForegroundColor Green
    $hasNpm = $true
} catch {
    Write-Host "  [WARN] node/npm is not installed. Skipping control-plane UI build." -ForegroundColor Yellow
}

if ($FailedTools -gt 0) {
    Write-Host ""
    Write-Host "  [ERROR] Required toolchains are missing. Please install them and re-run." -ForegroundColor Red
    exit 1
}

# 2. Rust Toolchain Checks
Write-Host ""
Write-Host "-- 2. Checking Rust Formatting and Linting -------------------------" -ForegroundColor Yellow
& cargo fmt --check
if ($LASTEXITCODE -ne 0) {
    Write-Host "  [FAIL] cargo fmt check failed" -ForegroundColor Red
    exit 1
}
Write-Host "  [OK] cargo fmt check passed" -ForegroundColor Green

& cargo clippy --all-targets -- -D warnings
if ($LASTEXITCODE -ne 0) {
    Write-Host "  [FAIL] cargo clippy check failed" -ForegroundColor Red
    exit 1
}
Write-Host "  [OK] cargo clippy passed with 0 warnings" -ForegroundColor Green

# 3. Rust Test Suite
Write-Host ""
Write-Host "-- 3. Running Rust Unit and Integration Tests ---------------------" -ForegroundColor Yellow
& cargo test --lib --bins
if ($LASTEXITCODE -ne 0) {
    Write-Host "  [FAIL] cargo tests failed" -ForegroundColor Red
    exit 1
}
Write-Host "  [OK] cargo test suite passed" -ForegroundColor Green

# 4. Go API validation if Go available
if ($hasGo -and (Test-Path "control-plane/api")) {
    Write-Host ""
    Write-Host "-- 4. Validating Control Plane Go API ----------------------------" -ForegroundColor Yellow
    Push-Location "control-plane/api"
    try {
        & go vet ./...
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  [FAIL] go vet failed" -ForegroundColor Red
            exit 1
        }
        Write-Host "  [OK] go vet passed on control-plane/api" -ForegroundColor Green
    } finally {
        Pop-Location
    }
}

# 5. UI Dashboard Build if Node available
if ($hasNpm -and (Test-Path "control-plane/ui")) {
    Write-Host ""
    Write-Host "-- 5. Validating Control Plane Web UI ---------------------------" -ForegroundColor Yellow
    Push-Location "control-plane/ui"
    try {
        if (-not (Test-Path "node_modules")) {
            & npm ci
        }
        & npm run build
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  [FAIL] npm run build failed" -ForegroundColor Red
            exit 1
        }
        Write-Host "  [OK] UI TypeScript build passed" -ForegroundColor Green
    } finally {
        Pop-Location
    }
}

Write-Host ""
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "  Bootstrap & Validation Successful! All environments verified." -ForegroundColor Green
Write-Host "====================================================================" -ForegroundColor Cyan
