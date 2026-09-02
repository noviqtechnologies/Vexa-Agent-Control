# PowerShell Installer for Vexa Agent Control Team OTET Enterprise Provisioning
param(
    [string]$Token,
    [string]$HubUrl,
    [string]$Env,
    [string]$Environment,
    [string]$Version,
    [switch]$Staging,
    [switch]$Stage,
    [switch]$Production,
    [switch]$Prod,
    [switch]$InstallService,
    [switch]$NoService
)

$ErrorActionPreference = "Stop"

$IsAdmin = $false
try {
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = [Security.Principal.WindowsPrincipal]$Identity
    $IsAdmin = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {}

$ColorGreen = "Green"
$ColorYellow = "Yellow"
$ColorCyan = "Cyan"
$ColorRed = "Red"

Write-Host "[*] Vexa Agent Control Team OTET Enterprise Provisioning Installer" -ForegroundColor $ColorCyan

if (!$Token) { $Token = $env:AGENTCONTROL_TOKEN }
if (!$Token) { $Token = $env:AGENTCONTROL_ENROLLMENT_TOKEN }
if (!$Token) { $Token = $env:AGENTWALL_TOKEN }
if (!$Token) { $Token = $env:AGENTWALL_ENROLLMENT_TOKEN }

$ProdHubUrl = "https://console.vexasec.io"
$StageHubUrl = "https://console-stage.vexasec.io"

if (!$Env) { $Env = $Environment }
if (!$Env) { $Env = $env:AGENTCONTROL_ENV }
if (!$Env) { $Env = $env:AGENTCONTROL_ENVIRONMENT }
if (!$Env) { $Env = $env:AGENTWALL_ENV }

if (!$HubUrl) {
    if ($Staging -or $Stage -or ($Env -and $Env.ToLower() -in @("staging", "stage"))) {
        $HubUrl = $StageHubUrl
    } elseif ($Production -or $Prod -or ($Env -and $Env.ToLower() -in @("production", "prod"))) {
        $HubUrl = $ProdHubUrl
    }
}

if (!$HubUrl) { $HubUrl = $env:AGENTCONTROL_HUB_URL }
if (!$HubUrl) { $HubUrl = $env:AGENTWALL_HUB_URL }
if (!$HubUrl -and $env:DASHBOARD_API_URL -and $env:DASHBOARD_API_URL -ne "http://localhost:8400") {
    $HubUrl = $env:DASHBOARD_API_URL
}

if ($HubUrl) {
    $HubTrimmed = $HubUrl.Trim().ToLower()
    if ($HubTrimmed -in @("staging", "stage", "https://console-stage.vexasec.io", "https://console-stage.vexasec.io/")) {
        $HubUrl = $StageHubUrl
    } elseif ($HubTrimmed -in @("production", "prod", "default", "https://console.vexasec.io", "https://console.vexasec.io/")) {
        $HubUrl = $ProdHubUrl
    }
}

if (!$HubUrl -or $HubUrl -eq "http://localhost:8400") {
    $HubUrl = $ProdHubUrl
}

$HubUrl = $HubUrl.TrimEnd('/')
$env:DASHBOARD_API_URL = $HubUrl
$env:AGENTCONTROL_HUB_URL = $HubUrl

if (!$Token) {
    Write-Host "[!] Error: Enterprise enrollment token required." -ForegroundColor $ColorRed
    Write-Host "    Pass -Token '<TOKEN>' or set `$env:AGENTCONTROL_TOKEN = '<TOKEN>' before running." -ForegroundColor $ColorYellow
    Write-Host "    Hub Endpoints: Production (-Prod / https://console.vexasec.io) | Staging (-Staging / https://console-stage.vexasec.io)" -ForegroundColor $ColorYellow
    exit 1
}

$ArchStr = "x86_64"
if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64" -or $env:PROCESSOR_ARCHITEW6432 -eq "ARM64") {
    $ArchStr = "aarch64"
}

$Repo = "noviqtechnologies/Vexa-Agent-Control"

if (!$Version) {
    $ReleasesUrl = "https://api.github.com/repos/$Repo/releases?per_page=1"
    try {
        $ReleaseJson = Invoke-RestMethod -Uri $ReleasesUrl -Headers @{ "User-Agent" = "AgentControl-Installer" }
        $Version = $ReleaseJson[0].tag_name
    } catch {
        $Version = "v1.0.65"
    }
    if (-not $Version) {
        $Version = "v1.0.70"
    }
}

if (!$Version.StartsWith("v")) {
    $Version = "v$Version"
}

Write-Host "[*] Version: $Version | Arch: $ArchStr | Hub: $HubUrl" -ForegroundColor $ColorGreen

$LocalBinDir = "$env:USERPROFILE\.local\bin"
if (!(Test-Path $LocalBinDir)) { New-Item -ItemType Directory -Path $LocalBinDir -Force | Out-Null }
$FinalBinaryPath = Join-Path $LocalBinDir "agentcontrol.exe"

$AssetName = "agentcontrol-$Version-windows-$ArchStr.zip"
$BaseUrl = "https://github.com/$Repo/releases/download/$Version"
$DownloadUrl = "$BaseUrl/$AssetName"
$ChecksumsUrl = "$BaseUrl/checksums.txt"
$TempZip = Join-Path $env:TEMP "agentcontrol_asset.zip"
$TempChecksums = Join-Path $env:TEMP "agentcontrol_checksums.txt"
$TempExtract = Join-Path $env:TEMP "agentcontrol_extract"
if (Test-Path $TempExtract) { Remove-Item $TempExtract -Recurse -Force | Out-Null }

Write-Host "[*] Downloading asset package: $DownloadUrl..." -ForegroundColor $ColorCyan
Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempZip -UseBasicParsing

Write-Host "[*] Verifying cryptographic SHA-256 checksum..." -ForegroundColor $ColorCyan
try {
    Invoke-WebRequest -Uri $ChecksumsUrl -OutFile $TempChecksums -UseBasicParsing
    $ChecksumsContent = Get-Content $TempChecksums -Raw
    $MatchedLine = ($ChecksumsContent -split "`n" | Where-Object { $_ -match [regex]::Escape($AssetName) } | Select-Object -First 1)
    if ($MatchedLine) {
        $ExpectedHash = ($MatchedLine.Trim() -split "\s+")[0].ToLower()
        $ActualHash = (Get-FileHash -Path $TempZip -Algorithm SHA256).Hash.ToLower()
        if ($ExpectedHash -ne $ActualHash) {
            Write-Host "[!] FATAL: Cryptographic Checksum Mismatch!" -ForegroundColor $ColorRed
            Write-Host "    Expected: $ExpectedHash" -ForegroundColor $ColorYellow
            Write-Host "    Got:      $ActualHash" -ForegroundColor $ColorYellow
            Remove-Item $TempZip -Force -ErrorAction SilentlyContinue
            exit 1
        }
        Write-Host "[+] SHA-256 Checksum verified successfully ($ActualHash)." -ForegroundColor $ColorGreen
    } else {
        Write-Host "[!] FATAL: Release asset $AssetName not listed in checksums.txt. Aborting." -ForegroundColor $ColorRed
        exit 1
    }
    Remove-Item $TempChecksums -Force -ErrorAction SilentlyContinue
} catch {
    Write-Host "[!] FATAL: Could not retrieve checksums.txt from $ChecksumsUrl. Aborting for security." -ForegroundColor $ColorRed
    exit 1
}

Expand-Archive -Path $TempZip -DestinationPath $TempExtract -Force

$ExtractedBin = Get-ChildItem -Path $TempExtract -Recurse -Filter "agentcontrol.exe" | Select-Object -First 1

# Gracefully stop running service and kill any lingering user processes to avoid binary file-lock
$RunningService = Get-Service AgentControlSentry -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }
if ($RunningService) {
    Write-Host "[*] Stopping active AgentControlSentry service for update..." -ForegroundColor $ColorYellow
    Stop-Service AgentControlSentry -Force -ErrorAction SilentlyContinue
}
Get-Process agentcontrol -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

try {
    Copy-Item -Path $ExtractedBin.FullName -Destination $FinalBinaryPath -Force
} catch {
    # If binary is locked by active session, rotate to .old and place fresh binary
    $OldBackup = "$FinalBinaryPath.old"
    Remove-Item $OldBackup -Force -ErrorAction SilentlyContinue
    Move-Item -Path $FinalBinaryPath -Destination $OldBackup -Force -ErrorAction SilentlyContinue
    Copy-Item -Path $ExtractedBin.FullName -Destination $FinalBinaryPath -Force
}
Remove-Item $TempZip -Force -ErrorAction SilentlyContinue

Write-Host "[*] Step 1/3: PKI Device Enrollment..." -ForegroundColor $ColorCyan
& $FinalBinaryPath enroll --token $Token --hub-url $HubUrl
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Device enrollment failed. Aborting provisioning." -ForegroundColor $ColorRed
    exit $LASTEXITCODE
}

$ShouldInstallService = (-not $NoService) -and ($InstallService -or $IsAdmin)

if ($ShouldInstallService) {
    Write-Host "[*] Step 2/3: Installing Persistent OS Sentry Service Daemon..." -ForegroundColor $ColorCyan
    try {
        # Sync user credentials to SYSTEM service profile if elevated
        $SystemAgentControl = "C:\Windows\System32\config\systemprofile\.agentcontrol"
        if (!(Test-Path $SystemAgentControl)) {
            New-Item -ItemType Directory -Path $SystemAgentControl -Force -ErrorAction SilentlyContinue | Out-Null
        }
        if (Test-Path "$env:USERPROFILE\.agentcontrol") {
            Copy-Item -Path "$env:USERPROFILE\.agentcontrol\*" -Destination $SystemAgentControl -Recurse -Force -ErrorAction SilentlyContinue
        }
        [Environment]::SetEnvironmentVariable("AGENTCONTROL_HUB_URL", $HubUrl, "Machine")
        [Environment]::SetEnvironmentVariable("DASHBOARD_API_URL", $HubUrl, "Machine")
        if ($env:GATEWAY_SECRET -and $env:GATEWAY_SECRET -ne "local-dev-shared-secret-change-me") {
            [Environment]::SetEnvironmentVariable("GATEWAY_SECRET", $env:GATEWAY_SECRET, "Machine")
        } else {
            [Environment]::SetEnvironmentVariable("GATEWAY_SECRET", $null, "Machine")
        }

        & $FinalBinaryPath service install --hub-url $HubUrl
    } catch {
        Write-Host "[!] Note: Sentry service installation failed: $_" -ForegroundColor $ColorYellow
    }
} else {
    Write-Host "[*] Step 2/3: Skipping system daemon installation (run in Administrator console or pass -InstallService to enable)." -ForegroundColor $ColorCyan
}

Write-Host "[*] Step 3/3: Auto-wrapping active IDE targets..." -ForegroundColor $ColorCyan
& $FinalBinaryPath wrap --all

Write-Host "`n[+] Automated Enterprise Provisioning Completed!" -ForegroundColor $ColorGreen
Write-Host "  - Version: $Version" -ForegroundColor $ColorGreen
Write-Host "  - SHA-256: $ActualHash" -ForegroundColor $ColorGreen
Write-Host "Get started by running:" -ForegroundColor $ColorGreen
Write-Host "  agentcontrol protect" -ForegroundColor $ColorGreen
Write-Host ""

