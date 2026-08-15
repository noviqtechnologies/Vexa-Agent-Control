# PowerShell Installer for AgentWall Team OTET Enterprise Provisioning
$ErrorActionPreference = "Stop"

$ColorGreen = "Green"
$ColorYellow = "Yellow"
$ColorCyan = "Cyan"
$ColorRed = "Red"

Write-Host "[*] AgentWall Team OTET Enterprise Provisioning Installer" -ForegroundColor $ColorCyan

$Token = $env:AGENTWALL_TOKEN
if (!$Token) { $Token = $env:AGENTWALL_ENROLLMENT_TOKEN }
$HubUrl = $env:DASHBOARD_API_URL
if (!$HubUrl) { $HubUrl = $env:AGENTWALL_HUB_URL }
if (!$HubUrl) { $HubUrl = "http://localhost:8400" }

if (!$Token) {
    Write-Host "[!] Error: Enterprise enrollment token required." -ForegroundColor $ColorRed
    Write-Host "    Set `$env:AGENTWALL_TOKEN = '<TOKEN>' before running this script." -ForegroundColor $ColorYellow
    exit 1
}

$ArchStr = "x86_64"
if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64" -or $env:PROCESSOR_ARCHITEW6432 -eq "ARM64") {
    $ArchStr = "aarch64"
}

$Repo = "noviqtechnologies/Vexa-Agent-Control"
$ReleasesUrl = "https://api.github.com/repos/$Repo/releases?per_page=1"

try {
    $ReleaseJson = Invoke-RestMethod -Uri $ReleasesUrl -Headers @{ "User-Agent" = "AgentWall-Installer" }
    $Version = $ReleaseJson[0].tag_name
} catch {
    Write-Host "[!] Failed to fetch version info: $_" -ForegroundColor $ColorRed
    exit 1
}

Write-Host "[*] Version: $Version | Hub: $HubUrl" -ForegroundColor $ColorGreen

$LocalBinDir = "$env:USERPROFILE\.local\bin"
if (!(Test-Path $LocalBinDir)) { New-Item -ItemType Directory -Path $LocalBinDir -Force | Out-Null }
$FinalBinaryPath = Join-Path $LocalBinDir "agentwall.exe"

$AssetName = "agentwall-$Version-windows-$ArchStr.zip"
$DownloadUrl = "https://github.com/$Repo/releases/download/$Version/$AssetName"
$TempZip = Join-Path $env:TEMP "agentwall_asset.zip"
$TempExtract = Join-Path $env:TEMP "agentwall_extract"
if (Test-Path $TempExtract) { Remove-Item $TempExtract -Recurse -Force | Out-Null }

Write-Host "[*] Downloading asset package..." -ForegroundColor $ColorCyan
Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempZip -UseBasicParsing
Expand-Archive -Path $TempZip -DestinationPath $TempExtract -Force

$ExtractedBin = Get-ChildItem -Path $TempExtract -Recurse -Filter "agentwall.exe" | Select-Object -First 1
Copy-Item -Path $ExtractedBin.FullName -Destination $FinalBinaryPath -Force
Remove-Item $TempZip -Force -ErrorAction SilentlyContinue

Write-Host "[*] Step 1/3: PKI Device Enrollment..." -ForegroundColor $ColorCyan
& $FinalBinaryPath enroll --token $Token --hub-url $HubUrl
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Device enrollment failed. Aborting provisioning." -ForegroundColor $ColorRed
    exit $LASTEXITCODE
}

Write-Host "[*] Step 2/3: Installing Persistent OS Sentry Service Daemon..." -ForegroundColor $ColorCyan
try {
    & $FinalBinaryPath service install --hub-url $HubUrl
} catch {
    Write-Host "[!] Note: Sentry service installation requires Administrator privileges." -ForegroundColor $ColorYellow
}

Write-Host "[*] Step 3/3: Auto-wrapping active IDE targets..." -ForegroundColor $ColorCyan
& $FinalBinaryPath wrap --all

Write-Host "`n[+] Automated Enterprise Provisioning Completed!" -ForegroundColor $ColorGreen
Write-Host "Get started by running:" -ForegroundColor $ColorGreen
Write-Host "  agentwall protect" -ForegroundColor $ColorGreen
Write-Host ""
