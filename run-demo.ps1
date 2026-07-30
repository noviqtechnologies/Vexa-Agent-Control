# AgentWall Dashboard Launcher (PowerShell - Windows / macOS / Linux with pwsh)
# Usage: .\run-demo.ps1   (Windows)   |   pwsh ./run-demo.ps1   (macOS/Linux)

$DASHBOARD_URL = "http://localhost:8081"
$LOGIN_EMAIL = "admin"

# Resolve compose file relative to this script's location
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$composeFile = Join-Path $scriptDir "control-plane\docker-compose.yml"

Write-Host ""
Write-Host "  Building and starting AgentWall Dashboard..." -ForegroundColor Cyan
Write-Host ""

docker compose -f "$composeFile" up --detach --build

if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "  [ERROR] docker compose failed. Check the output above." -ForegroundColor Red
    exit 1
}

# Wait for the dashboard API to become healthy
Write-Host ""
Write-Host "  Waiting for services to become healthy..." -ForegroundColor DarkCyan

$maxAttempts = 30
$attempt = 0
$ready = $false

while ($attempt -lt $maxAttempts) {
    Start-Sleep -Seconds 3
    $attempt++
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8400/healthz" -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
        if ($response.StatusCode -eq 200) {
            $ready = $true
            break
        }
    }
    catch {
        # Still starting up - keep waiting
    }
    Write-Host "  [$attempt/$maxAttempts] Still starting..." -ForegroundColor DarkGray
}

Write-Host ""

if (-not $ready) {
    Write-Host "  [WARN] API did not respond after $($maxAttempts * 3)s." -ForegroundColor Yellow
    Write-Host "  Check logs: docker compose -f `"$composeFile`" logs" -ForegroundColor Yellow
}

# Fetch the bootstrap token from container logs
# The API prints it when no auth providers are configured (fresh install)
$BOOTSTRAP_TOKEN = ""
$logs = docker compose -f "$composeFile" logs dashboard-api 2>&1
foreach ($line in $logs) {
    if ($line -match "Bootstrap Token:\s+(\S+)") {
        $BOOTSTRAP_TOKEN = $Matches[1]
        break
    }
}

# Print access summary banner
$line = "-" * 62
Write-Host "  $line" -ForegroundColor DarkGray
Write-Host ""
Write-Host "   AgentWall Dashboard is ready!" -ForegroundColor Green
Write-Host ""
Write-Host "   Dashboard URL   " -ForegroundColor Gray -NoNewline
Write-Host $DASHBOARD_URL       -ForegroundColor Yellow
Write-Host ""
Write-Host "   Login Email     " -ForegroundColor Gray -NoNewline
Write-Host $LOGIN_EMAIL         -ForegroundColor Cyan
Write-Host ""
if ($BOOTSTRAP_TOKEN -ne "") {
    Write-Host "   Bootstrap Token " -ForegroundColor Gray -NoNewline
    Write-Host $BOOTSTRAP_TOKEN     -ForegroundColor Green
}
else {
    Write-Host "   Bootstrap Token " -ForegroundColor Gray -NoNewline
    Write-Host "(auth provider configured - use your credentials)" -ForegroundColor DarkYellow
}
Write-Host ""
Write-Host "  $line" -ForegroundColor DarkGray
Write-Host ""
Write-Host "   Tail logs : docker compose -f `"$composeFile`" logs -f" -ForegroundColor DarkGray
Write-Host "   Stop      : docker compose -f `"$composeFile`" down"    -ForegroundColor DarkGray
Write-Host ""
