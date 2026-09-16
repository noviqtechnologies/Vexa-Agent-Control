# PowerShell Installer for Vexa Agent Control CLI Workstation
$ErrorActionPreference = "Stop"

$ColorGreen = "Green"
$ColorYellow = "Yellow"
$ColorCyan = "Cyan"
$ColorRed = "Red"

Write-Host "[*] Vexa Agent Control CLI Workstation Installer" -ForegroundColor $ColorCyan

$ArchStr = "x86_64"
if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64" -or $env:PROCESSOR_ARCHITEW6432 -eq "ARM64") {
    $ArchStr = "aarch64"
}

$Repo = "noviqtechnologies/Vexa-Agent-Control"
$ReleasesUrl = "https://api.github.com/repos/$Repo/releases/latest"

Write-Host "[*] Fetching latest release version..." -ForegroundColor $ColorCyan
$FallbackVersion = "v1.0.85"
$Version = $null
try {
    $ReleaseJson = Invoke-RestMethod -Uri $ReleasesUrl -Headers @{ "User-Agent" = "AgentControl-Installer" }
    $Version = $ReleaseJson.tag_name
} catch {
    Write-Host "[!] Notice: GitHub API resolution failed. Falling back to: $FallbackVersion" -ForegroundColor $ColorYellow
    $Version = $FallbackVersion
}
if (-not $Version) { $Version = $FallbackVersion }
if (-not $Version.StartsWith("v")) { $Version = "v$Version" }

Write-Host "[*] Using version: $Version" -ForegroundColor $ColorGreen

$LocalBinDir = "$env:USERPROFILE\.local\bin"
if (!(Test-Path $LocalBinDir)) {
    New-Item -ItemType Directory -Path $LocalBinDir -Force | Out-Null
}

$BinaryName = "agentcontrol.exe"
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

$RawVer = $Version.TrimStart("v")
if ($InstalledVersion -and $InstalledVersion -eq $RawVer) {
    Write-Host "[✓] Vexa Agent Control $Version is already installed." -ForegroundColor $ColorGreen
} else {
    if ($InstalledVersion) {
        Write-Host "[*] Upgrading Vexa Agent Control $InstalledVersion -> $Version..." -ForegroundColor $ColorYellow
    } else {
        Write-Host "[*] Fresh install of Vexa Agent Control $Version..." -ForegroundColor $ColorCyan
    }

    $AssetName = "agentcontrol-$Version-windows-$ArchStr.zip"
    $DownloadUrl = "https://github.com/$Repo/releases/download/$Version/$AssetName"

    $TempZip = Join-Path $env:TEMP "agentcontrol_asset.zip"
    $TempExtract = Join-Path $env:TEMP "agentcontrol_extract"
    if (Test-Path $TempExtract) { Remove-Item $TempExtract -Recurse -Force | Out-Null }

    Write-Host "[*] Downloading $DownloadUrl..." -ForegroundColor $ColorCyan
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempZip -UseBasicParsing

    Expand-Archive -Path $TempZip -DestinationPath $TempExtract -Force

    $ExtractedBin = Get-ChildItem -Path $TempExtract -Recurse -Filter "agentcontrol.exe" | Select-Object -First 1
    if (!$ExtractedBin) {
        Write-Host "[!] Could not find agentcontrol.exe in archive." -ForegroundColor $ColorRed
        exit 1
    }

    Copy-Item -Path $ExtractedBin.FullName -Destination $FinalBinaryPath -Force
    Remove-Item $TempZip -Force -ErrorAction SilentlyContinue

    Write-Host "[✓] Installed binary to $FinalBinaryPath" -ForegroundColor $ColorGreen
}

# Ensure LocalBinDir is on PATH
$CurrentPath = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::User)
if ($CurrentPath -notlike "*$LocalBinDir*") {
    $NewPath = "$LocalBinDir;$CurrentPath".Replace(";;", ";")
    [Environment]::SetEnvironmentVariable("PATH", $NewPath, [EnvironmentVariableTarget]::User)
    $env:Path = "$LocalBinDir;$env:Path"
}

Write-Host "`nGet started by running:" -ForegroundColor $ColorGreen
Write-Host "  agentcontrol login" -ForegroundColor $ColorGreen
Write-Host "  agentcontrol connect codex" -ForegroundColor $ColorGreen
Write-Host "  agentcontrol doctor" -ForegroundColor $ColorGreen
Write-Host ""
