# PowerShell Installer for AgentWall CLI Workstation
$ErrorActionPreference = "Stop"

$ColorGreen = "Green"
$ColorYellow = "Yellow"
$ColorCyan = "Cyan"
$ColorRed = "Red"

Write-Host "[*] AgentWall CLI Workstation Installer" -ForegroundColor $ColorCyan

$ArchStr = "x86_64"
if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64" -or $env:PROCESSOR_ARCHITEW6432 -eq "ARM64") {
    $ArchStr = "aarch64"
}

$Repo = "noviqtechnologies/Vexa-Agent-Control"

Write-Host "[*] Fetching latest release version..." -ForegroundColor $ColorCyan
$ReleasesUrl = "https://api.github.com/repos/$Repo/releases?per_page=1"
try {
    $ReleaseJson = Invoke-RestMethod -Uri $ReleasesUrl -Headers @{ "User-Agent" = "AgentWall-Installer" }
    $Version = $ReleaseJson[0].tag_name
} catch {
    Write-Host "[!] Failed to fetch version info: $_" -ForegroundColor $ColorRed
    exit 1
}

Write-Host "[*] Using version: $Version" -ForegroundColor $ColorGreen

$LocalBinDir = "$env:USERPROFILE\.local\bin"
if (!(Test-Path $LocalBinDir)) {
    New-Item -ItemType Directory -Path $LocalBinDir -Force | Out-Null
}

$BinaryName = "agentwall.exe"
$FinalBinaryPath = Join-Path $LocalBinDir $BinaryName

$InstalledVersion = $null
if (Test-Path $FinalBinaryPath) {
    try {
        $VerOutput = & $FinalBinaryPath --version 2>&1 | Out-String
        if ($VerOutput -match "(\d+\.\d+\.\d+)") {
            $InstalledVersion = $Matches[1]
        }
    } catch { }
}

if ($InstalledVersion -and "v$InstalledVersion" -eq $Version) {
    Write-Host "[✓] AgentWall $Version is already installed." -ForegroundColor $ColorGreen
} else {
    if ($InstalledVersion) {
        Write-Host "[*] Upgrading AgentWall $InstalledVersion -> $Version..." -ForegroundColor $ColorYellow
    } else {
        Write-Host "[*] Fresh install of AgentWall $Version..." -ForegroundColor $ColorCyan
    }

    $AssetName = "agentwall-$Version-windows-$ArchStr.zip"
    $DownloadUrl = "https://github.com/$Repo/releases/download/$Version/$AssetName"

    $TempZip = Join-Path $env:TEMP "agentwall_asset.zip"
    $TempExtract = Join-Path $env:TEMP "agentwall_extract"
    if (Test-Path $TempExtract) { Remove-Item $TempExtract -Recurse -Force | Out-Null }

    Write-Host "[*] Downloading $DownloadUrl..." -ForegroundColor $ColorCyan
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempZip -UseBasicParsing

    Expand-Archive -Path $TempZip -DestinationPath $TempExtract -Force

    $ExtractedBin = Get-ChildItem -Path $TempExtract -Recurse -Filter "agentwall.exe" | Select-Object -First 1
    if (!$ExtractedBin) {
        Write-Host "[!] Could not find agentwall.exe in archive." -ForegroundColor $ColorRed
        exit 1
    }

    Copy-Item -Path $ExtractedBin.FullName -Destination $FinalBinaryPath -Force
    Remove-Item $TempZip -Force -ErrorAction SilentlyContinue

    Write-Host "[✓] Installed binary to $FinalBinaryPath" -ForegroundColor $ColorGreen
}

Write-Host "`nGet started by running:" -ForegroundColor $ColorGreen
Write-Host "  agentwall protect" -ForegroundColor $ColorGreen
Write-Host "  agentwall --version"
Write-Host ""
