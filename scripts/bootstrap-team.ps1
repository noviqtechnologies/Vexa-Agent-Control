# Vexa Agent Control - Small-Team Production Secret Bootstrapper (DEP-002)
# Generates cryptographically secure CSPRNG secrets and produces a hardened .env file.

param(
    [string]$EnvFile = ".env",
    [string]$Domain = "localhost",
    [string]$AdminEmail = "admin@vexa.local",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Generate-CSPRNGHex([int]$Bytes) {
    $Buffer = New-Object byte[] $Bytes
    $Rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $Rng.GetBytes($Buffer)
    return ($Buffer | ForEach-Object { $_.ToString("x2") }) -join ""
}

function Generate-CSPRNGPassword([int]$Length = 24) {
    $Chars = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*"
    $Buffer = New-Object byte[] $Length
    $Rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $Rng.GetBytes($Buffer)
    $Result = ""
    for ($i = 0; $i -lt $Length; $i++) {
        $Idx = $Buffer[$i] % $Chars.Length
        $Result += $Chars[$Idx]
    }
    return $Result
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Vexa Agent Control - CSPRNG Production Secret Bootstrapper" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

if ((Test-Path $EnvFile) -and (-not $Force)) {
    Write-Host "[!] Target file '$EnvFile' already exists. Use -Force to overwrite." -ForegroundColor Yellow
    exit 1
}

Write-Host "[*] Generating cryptographically secure random secrets..." -ForegroundColor Green

$PostgresPassword = Generate-CSPRNGHex 24
$GatewaySecret = Generate-CSPRNGHex 32
$PolicyReadSecret = Generate-CSPRNGHex 32
$ProviderKeyEncryptionSecret = Generate-CSPRNGHex 32
$SessionSecret = Generate-CSPRNGHex 32
$AdminPassword = Generate-CSPRNGPassword 24
$IngressAuthSecret = Generate-CSPRNGHex 32

$GenDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss UTC")

$Text = @"
# ==============================================================================
# Vexa Agent Control - Production Team Environment Configuration (Generated)
# Generated: $GenDate
# ==============================================================================

# Hub Deployment Domain
HUB_DOMAIN=$Domain

# Database Credentials
POSTGRES_USER=vexa
POSTGRES_PASSWORD=$PostgresPassword
POSTGRES_DB=vexa_control_plane

# Internal Cluster & Gateway Secrets (32-byte CSPRNG)
GATEWAY_SECRET=$GatewaySecret
POLICY_READ_SECRET=$PolicyReadSecret
PROVIDER_KEY_ENCRYPTION_SECRET=$ProviderKeyEncryptionSecret
AGENTCONTROL_SESSION_SECRET=$SessionSecret
INGRESS_AUTH_SECRET=$IngressAuthSecret

# Initial Hub Administrator
SAAS_OPERATOR_EMAIL=$AdminEmail
SAAS_OPERATOR_PASSWORD=$AdminPassword

# Strict Production Enforcement (halt boot on placeholder credentials)
DEV_MODE=false
"@

$OutPath = if ([System.IO.Path]::IsPathRooted($EnvFile)) { $EnvFile } else { Join-Path (Get-Location).Path $EnvFile }
[System.IO.File]::WriteAllText($OutPath, $Text, [System.Text.Encoding]::UTF8)

Write-Host "[+] Secure production environment written to $EnvFile" -ForegroundColor Green
Write-Host "    Admin Email    : $AdminEmail" -ForegroundColor Cyan
Write-Host "    Admin Password : $AdminPassword" -ForegroundColor Yellow
Write-Host "    Domain         : $Domain" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next step: launch the secure team stack with:" -ForegroundColor Green
Write-Host "    docker compose -f docker-compose.team.secure.yml up -d" -ForegroundColor White
