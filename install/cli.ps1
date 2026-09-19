# PowerShell Installer for Vexa Agent Control CLI Workstation
$ErrorActionPreference = "Stop"

# Force TLS 1.2 — required by GitHub releases
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$ColorGreen = "Green"
$ColorYellow = "Yellow"
$ColorCyan = "Cyan"
$ColorRed = "Red"

Write-Host "[*] Vexa Agent Control CLI Workstation Installer" -ForegroundColor $ColorCyan

$ArchMap = @{
    "AMD64" = "x86_64"
    "ARM64" = "aarch64"
}
$ArchEnv = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64" -or $env:PROCESSOR_ARCHITEW6432 -eq "ARM64") { "ARM64" } else { "AMD64" }
$ArchStr = $ArchMap[$ArchEnv]
if (-not $ArchStr) { $ArchStr = "x86_64" }

$Repo = "noviqtechnologies/Vexa-Agent-Control"
$ReleasesUrl = "https://api.github.com/repos/$Repo/releases/latest"
$FallbackVersion = "v1.0.89"

Write-Host "[*] Fetching latest release version..." -ForegroundColor $ColorCyan
$Version = $null
try {
    $ReleaseJson = Invoke-RestMethod -Uri $ReleasesUrl -Headers @{ "User-Agent" = "AgentControl-Installer" }
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
        Write-Host "[!] Notice: GitHub API resolution failed. Falling back to: $FallbackVersion" -ForegroundColor $ColorYellow
        $Version = $FallbackVersion
    }
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
    Write-Host "[+] Vexa Agent Control $Version is already installed." -ForegroundColor $ColorGreen
} else {
    if ($InstalledVersion) {
        Write-Host "[*] Upgrading Vexa Agent Control $InstalledVersion -> $Version..." -ForegroundColor $ColorYellow
    } else {
        Write-Host "[*] Fresh install of Vexa Agent Control $Version..." -ForegroundColor $ColorCyan
    }

    $AssetName = "agentcontrol-$Version-windows-$ArchStr.zip"
    $BaseUrl = "https://github.com/$Repo/releases/download/$Version"
    $DownloadUrl = "$BaseUrl/$AssetName"
    $ChecksumsUrl = "$BaseUrl/checksums.txt"

    $TempZip = Join-Path $env:TEMP "agentcontrol_asset.zip"
    $TempChecksums = Join-Path $env:TEMP "agentcontrol_checksums.txt"
    $TempExtract = Join-Path $env:TEMP "agentcontrol_extract"
    if (Test-Path $TempExtract) { Remove-Item $TempExtract -Recurse -Force -ErrorAction SilentlyContinue }

    Write-Host "[*] Downloading $DownloadUrl..." -ForegroundColor $ColorCyan
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $TempZip -UseBasicParsing

    # Checksum Verification
    Write-Host "[*] Verifying cryptographic SHA-256 checksum..." -ForegroundColor $ColorCyan
    try {
        Invoke-WebRequest -Uri $ChecksumsUrl -OutFile $TempChecksums -UseBasicParsing
        $ChecksumsContent = Get-Content $TempChecksums -Raw
        $MatchedLine = ($ChecksumsContent -split "`n" | Where-Object { $_ -match [regex]::Escape($AssetName) } | Select-Object -First 1)
        if ($MatchedLine) {
            $ExpectedHash = ($MatchedLine.Trim() -split "\s+")[0].ToUpper()
            $ActualHash = (Get-FileHash -Path $TempZip -Algorithm SHA256).Hash.ToUpper()
            if ($ExpectedHash -ne $ActualHash) {
                Write-Host "[!] Checksum mismatch!" -ForegroundColor $ColorRed
                exit 1
            }
            Write-Host "[+] Cryptographic SHA-256 checksum verified." -ForegroundColor $ColorGreen
        }
        Remove-Item $TempChecksums -Force -ErrorAction SilentlyContinue
    } catch { }

    Expand-Archive -Path $TempZip -DestinationPath $TempExtract -Force

    $ExtractedBin = Get-ChildItem -Path $TempExtract -Recurse -Filter "agentcontrol.exe" | Select-Object -First 1
    if (!$ExtractedBin) {
        $ExtractedBin = Get-ChildItem -Path $TempExtract -Recurse -Filter "agentcontrol*" | Where-Object { -not $_.PSIsContainer } | Select-Object -First 1
    }

    if (!$ExtractedBin) {
        Write-Host "[!] Could not find agentcontrol.exe in archive." -ForegroundColor $ColorRed
        exit 1
    }

    # Stop running service/process if present to prevent locked file errors
    $RunningService = Get-Service AgentControlSentry -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }
    if ($RunningService) {
        Stop-Service AgentControlSentry -Force -ErrorAction SilentlyContinue
    }
    Get-Process agentcontrol -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300

    try {
        Copy-Item -Path $ExtractedBin.FullName -Destination $FinalBinaryPath -Force
    } catch {
        $OldBackup = "$FinalBinaryPath.old"
        Remove-Item $OldBackup -Force -ErrorAction SilentlyContinue
        Move-Item -Path $FinalBinaryPath -Destination $OldBackup -Force -ErrorAction SilentlyContinue
        Copy-Item -Path $ExtractedBin.FullName -Destination $FinalBinaryPath -Force
    }

    $QuickstartScript = Get-ChildItem -Path $TempExtract -Recurse -Filter "quickstart_agent.py" | Select-Object -First 1
    if ($QuickstartScript) {
        try {
            Copy-Item -Path $QuickstartScript.FullName -Destination (Join-Path $LocalBinDir "quickstart_agent.py") -Force -ErrorAction SilentlyContinue
        } catch { }
    }

    Remove-Item $TempZip -Force -ErrorAction SilentlyContinue
    Remove-Item $TempExtract -Recurse -Force -ErrorAction SilentlyContinue | Out-Null

    Write-Host "[+] Installed binary to $FinalBinaryPath" -ForegroundColor $ColorGreen
}

# Ensure LocalBinDir is on PATH
$CurrentPath = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::User)
if ($CurrentPath -notlike "*$LocalBinDir*") {
    $NewPath = "$LocalBinDir;$CurrentPath" -replace ";+", ";"
    [Environment]::SetEnvironmentVariable("PATH", $NewPath, [EnvironmentVariableTarget]::User)
    $env:Path = "$LocalBinDir;$env:Path"
}

Write-Host "`nGet started by running:" -ForegroundColor $ColorGreen
Write-Host "  agentcontrol login" -ForegroundColor $ColorGreen
Write-Host "  agentcontrol connect codex" -ForegroundColor $ColorGreen
Write-Host "  agentcontrol doctor" -ForegroundColor $ColorGreen
Write-Host ""
