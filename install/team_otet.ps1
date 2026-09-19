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

# Force TLS 1.2 — required by GitHub releases
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

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

$ArchMap = @{
    "AMD64" = "x86_64"
    "ARM64" = "aarch64"
}
$ArchEnv = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64" -or $env:PROCESSOR_ARCHITEW6432 -eq "ARM64") { "ARM64" } else { "AMD64" }
$ArchStr = $ArchMap[$ArchEnv]
if (-not $ArchStr) { $ArchStr = "x86_64" }

$Repo = "noviqtechnologies/Vexa-Agent-Control"
$FallbackVersion = "v1.0.88"

if (!$Version) {
    Write-Host "[*] Fetching latest release version from GitHub..." -ForegroundColor $ColorCyan
    try {
        $ReleaseJson = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" `
            -Headers @{ "User-Agent" = "AgentControl-Installer" }
        $Version = $ReleaseJson.tag_name
    } catch {
        # Secondary: HTTP Redirect Scraping
        try {
            $Req = [System.Net.WebRequest]::Create("https://github.com/$Repo/releases/latest")
            $Req.AllowAutoRedirect = $false
            $Resp = $Req.GetResponse()
            $Location = $Resp.GetResponseHeader("Location")
            $Resp.Close()
            if ($Location -match "tag/(v?[0-9.]+)") {
                $Version = $Matches[1]
            }
        } catch { }

        if (-not $Version) {
            $Version = $FallbackVersion
        }
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
$MaxRetries = 3
for ($i = 1; $i -le $MaxRetries; $i++) {
    try {
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempZip -UseBasicParsing
        break
    } catch {
        if ($i -eq $MaxRetries) {
            Write-Host "Download failed after $MaxRetries attempts: $_" -ForegroundColor $ColorRed
            throw "Failed to download $DownloadUrl"
        }
        Write-Host "Attempt $i failed, retrying in $($i * 2)s..." -ForegroundColor $ColorYellow
        Start-Sleep -Seconds ($i * 2)
    }
}

Write-Host "[*] Verifying cryptographic SHA-256 checksum..." -ForegroundColor $ColorCyan
try {
    Invoke-WebRequest -Uri $ChecksumsUrl -OutFile $TempChecksums -UseBasicParsing
    $ChecksumsContent = Get-Content $TempChecksums -Raw
    $MatchedLine = ($ChecksumsContent -split "`n" | Where-Object { $_ -match [regex]::Escape($AssetName) } | Select-Object -First 1)
    if ($MatchedLine) {
        $ExpectedHash = ($MatchedLine.Trim() -split "\s+")[0].ToUpper()
        $ActualHash = (Get-FileHash -Path $TempZip -Algorithm SHA256).Hash.ToUpper()
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

$ExtractedBin = Get-ChildItem -Path $TempExtract -Recurse -Filter "agentcontrol.exe" |
    Where-Object { -not $_.PSIsContainer } | Select-Object -First 1
if (-not $ExtractedBin) {
    $ExtractedBin = Get-ChildItem -Path $TempExtract -Recurse -Filter "agentcontrol*" |
        Where-Object { -not $_.PSIsContainer } | Select-Object -First 1
}

# Gracefully stop running service and kill any lingering user processes to avoid binary file-lock
$RunningService = Get-Service AgentControlSentry -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }
if ($RunningService) {
    Write-Host "[*] Stopping active AgentControlSentry service for update..." -ForegroundColor $ColorYellow
    Stop-Service AgentControlSentry -Force -ErrorAction SilentlyContinue
}
Get-Process agentcontrol -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 300

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
Remove-Item $TempExtract -Recurse -Force -ErrorAction SilentlyContinue | Out-Null

# Update PATH
$CurrentPath = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::User)
if ($CurrentPath -notlike "*$LocalBinDir*") {
    $NewPath = "$LocalBinDir;$CurrentPath".Replace(";;", ";")
    [Environment]::SetEnvironmentVariable("PATH", $NewPath, [EnvironmentVariableTarget]::User)
    $env:Path = "$LocalBinDir;$env:Path"
}

Write-Host "[*] Step 1/3: PKI Device Enrollment..." -ForegroundColor $ColorCyan
& $FinalBinaryPath enroll --token $Token --hub-url $HubUrl
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Device enrollment failed. Aborting provisioning." -ForegroundColor $ColorRed
    exit $LASTEXITCODE
}

$ShouldInstallService = (-not $NoService) -and ($InstallService -or $IsAdmin)

if ($ShouldInstallService) {
    Write-Host "[*] Step 2/3: Installing Persistent Per-User Background Daemon..." -ForegroundColor $ColorCyan
    try {
        [Environment]::SetEnvironmentVariable("AGENTCONTROL_HUB_URL", $HubUrl, "User")
        & $FinalBinaryPath service install --hub-url $HubUrl
    } catch {
        Write-Host "[!] Note: Daemon service installation note: $_" -ForegroundColor $ColorYellow
    }
} else {
    Write-Host "[*] Step 2/3: Skipping daemon installation (pass -InstallService to enable)." -ForegroundColor $ColorCyan
}

Write-Host "[*] Step 3/3: Running diagnostic health verification..." -ForegroundColor $ColorCyan
& $FinalBinaryPath doctor

Write-Host "`n[+] Automated Enterprise Provisioning Completed!" -ForegroundColor $ColorGreen
Write-Host "  - Version: $Version" -ForegroundColor $ColorGreen
Write-Host "  - SHA-256: $ActualHash" -ForegroundColor $ColorGreen
Write-Host "Next steps:" -ForegroundColor $ColorGreen
Write-Host "  agentcontrol status" -ForegroundColor $ColorGreen
Write-Host "  agentcontrol connect codex" -ForegroundColor $ColorGreen
Write-Host ""
