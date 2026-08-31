<#
.SYNOPSIS
    Vexa Agent Control Binary Installer for Windows (Standalone Developer Edition).
    Usage: irm https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.ps1 | iex
           .\install.ps1 [-Version <VERSION>]    # omit -Version to install the latest release
#>

param(
    [string]$Version = $env:AGENTCONTROL_VERSION
)

& {
    $ErrorActionPreference = "Stop"

    # Force TLS 1.2 — required by GitHub releases
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $ColorCyan = "Cyan"
    $ColorGreen = "Green"
    $ColorRed = "Red"
    $ColorYellow = "Yellow"

    Write-Host "=============================================" -ForegroundColor $ColorCyan
    Write-Host "          Vexa Agent Control Installer              " -ForegroundColor $ColorCyan
    Write-Host "=============================================" -ForegroundColor $ColorCyan

    $InstallDir = Join-Path $env:USERPROFILE ".local\bin"
    $Repo = "noviqtechnologies/Vexa-Agent-Control"

    # Resolve version: use provided value, env var, or fetch latest from GitHub
    $FallbackVersion = "v1.0.70"
    if (-not $Version) { $Version = $env:AGENTCONTROL_VERSION }
    if (-not $Version) {
        Write-Host "[*] Fetching latest release version from GitHub..." -ForegroundColor $ColorCyan
        try {
            $ReleaseJson = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" `
                -Headers @{ "User-Agent" = "AgentControl-Installer" }
            $Version = $ReleaseJson.tag_name
        }
        catch {
            Write-Host "[!] Notice: GitHub API resolution failed (rate-limited or offline)." -ForegroundColor $ColorYellow
            Write-Host "    Falling back to default release: $FallbackVersion" -ForegroundColor $ColorYellow
            $Version = $FallbackVersion
        }
        Write-Host "[*] Target version: $Version" -ForegroundColor $ColorGreen
    }
    if (-not $Version.StartsWith("v")) { $Version = "v$Version" }

    # 1. Detect Architecture
    $ArchMap = @{
        "AMD64" = "x86_64"
        "ARM64" = "aarch64"
    }
    $ArchEnv = $env:PROCESSOR_ARCHITECTURE
    $ArchTarget = $ArchMap[$ArchEnv]

    if (-not $ArchTarget) {
        Write-Host "Unsupported Architecture: $ArchEnv" -ForegroundColor $ColorRed
        throw "Unsupported Architecture: $ArchEnv"
    }

    if ($ArchTarget -eq "aarch64") {
        Write-Host "[!] Notice: Native Windows ARM64 binaries are experimental and require release asset agentcontrol-$Version-windows-aarch64.zip." -ForegroundColor $ColorYellow
    }

    Write-Host "Platform detected: windows-$ArchTarget" -ForegroundColor $ColorGreen
    Write-Host "Target version: $Version" -ForegroundColor $ColorGreen

    # 2. Check currently installed version
    $FinalBinaryPath = Join-Path $InstallDir "agentcontrol.exe"
    $InstalledVersion = $null
    if (Test-Path $FinalBinaryPath) {
        try {
            $InstalledVersion = (& $FinalBinaryPath --version 2>$null) -replace '[^0-9.]', '' | Select-Object -First 1
        }
        catch { $InstalledVersion = $null }
    }

    $RawVer = $Version.TrimStart("v")
    if ($InstalledVersion -and $InstalledVersion -eq $RawVer) {
        Write-Host "`n[+] Vexa Agent Control v$RawVer is already up to date. Nothing to do." -ForegroundColor $ColorGreen
        return
    }
    elseif ($InstalledVersion) {
        Write-Host "Upgrading $InstalledVersion -> $RawVer..." -ForegroundColor $ColorCyan
    }
    else {
        Write-Host "Fresh install of Vexa Agent Control $Version..." -ForegroundColor $ColorCyan
    }

    $AssetName = "agentcontrol-$Version-windows-$ArchTarget.zip"
    $BaseUrl = "https://github.com/$Repo/releases/download/$Version"
    $AssetUrl = "$BaseUrl/$AssetName"
    $ChecksumsUrl = "$BaseUrl/checksums.txt"

    # 3. Create Temp Dir
    $TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "AgentControlInstall"
    if (Test-Path $TempDir) { Remove-Item $TempDir -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $TempDir | Out-Null

    # 4. Download ZIP (with retry)
    $ZipPath = Join-Path $TempDir $AssetName
    $ChecksumsPath = Join-Path $TempDir "checksums.txt"

    Write-Host "Downloading $AssetName..."
    $MaxRetries = 3
    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            Invoke-WebRequest -Uri $AssetUrl -OutFile $ZipPath -UseBasicParsing
            break
        }
        catch {
            if ($i -eq $MaxRetries) {
                Write-Host "Download failed after $MaxRetries attempts: $_" -ForegroundColor $ColorRed
                throw "Failed to download $AssetUrl"
            }
            Write-Host "Attempt $i failed, retrying in $($i * 2)s..." -ForegroundColor $ColorYellow
            Start-Sleep -Seconds ($i * 2)
        }
    }

    # 5. Checksum Verification (Fail-Closed)
    Write-Host "Verifying SHA-256 cryptographic checksum..." -ForegroundColor $ColorCyan
    try {
        Invoke-WebRequest -Uri $ChecksumsUrl -OutFile $ChecksumsPath -UseBasicParsing
    }
    catch {
        Write-Host "[!] FATAL: Checksum manifest not published for release $Version." -ForegroundColor $ColorRed
        Write-Host "    Installation halted in accordance with strict security posture." -ForegroundColor $ColorRed
        throw "Checksum manifest missing."
    }

    $ExpectedHashStr = (Get-Content $ChecksumsPath | Where-Object { $_ -match $AssetName })
    if (-not $ExpectedHashStr) {
        Write-Host "[!] FATAL: Asset $AssetName is not listed in checksums.txt." -ForegroundColor $ColorRed
        throw "Release asset digest missing from manifest."
    }

    $ExpectedHash = ($ExpectedHashStr -split '\s+')[0].Trim().ToUpper()
    $ActualHash = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash.ToUpper()

    if ($ExpectedHash -ne $ActualHash) {
        Write-Host "[!] FATAL: Cryptographic Checksum Mismatch!" -ForegroundColor $ColorRed
        Write-Host "    Expected: $ExpectedHash" -ForegroundColor $ColorRed
        Write-Host "    Got:      $ActualHash" -ForegroundColor $ColorRed
        throw "Cryptographic SHA-256 Checksum Mismatch!"
    }
    Write-Host "[✓] Cryptographic SHA-256 checksum verified: $ActualHash" -ForegroundColor $ColorGreen

    # 6. Extract ZIP
    Write-Host "Extracting archive..."
    $ExtractDir = Join-Path $TempDir "extracted"
    Expand-Archive -Path $ZipPath -DestinationPath $ExtractDir -Force

    $ExtractedBinary = Get-ChildItem -Path $ExtractDir -Recurse -Filter "agentcontrol*" |
    Where-Object { -not $_.PSIsContainer } | Select-Object -First 1

    if (-not $ExtractedBinary) {
        Write-Host "Could not locate agentcontrol binary inside extracted archive." -ForegroundColor $ColorRed
        throw "Binary missing in archive"
    }

    # 7. Install
    Write-Host "Installing to $InstallDir..."
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    }

    $AgentControlPath = Join-Path $InstallDir "agentcontrol.exe"
    Copy-Item -Path $ExtractedBinary.FullName -Destination $AgentControlPath -Force
    Copy-Item -Path $ExtractedBinary.FullName -Destination $FinalBinaryPath -Force

    $QuickstartScript = Get-ChildItem -Path $ExtractDir -Recurse -Filter "quickstart_agent.py" | Select-Object -First 1
    $QuickstartTarget = Join-Path $InstallDir "quickstart_agent.py"
    if ($QuickstartScript) {
        Copy-Item -Path $QuickstartScript.FullName -Destination $QuickstartTarget -Force
    }

    # Update PATH
    $CurrentPath = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::User)
    if ($CurrentPath -notlike "*$InstallDir*") {
        $NewPath = "$InstallDir;$CurrentPath".Replace(";;", ";")
        [Environment]::SetEnvironmentVariable("PATH", $NewPath, [EnvironmentVariableTarget]::User)
        $env:Path = "$InstallDir;$env:Path"
    }

    Remove-Item $TempDir -Recurse -Force | Out-Null

    Write-Host ""
    Write-Host "┌────────────────────────────────────────────────────────────────────────┐" -ForegroundColor $ColorCyan
    Write-Host "│  ✨ Vexa Agent Control $Version successfully installed!                 │" -ForegroundColor $ColorCyan
    Write-Host "├────────────────────────────────────────────────────────────────────────┤" -ForegroundColor $ColorCyan
    Write-Host "│  Binary Location : $FinalBinaryPath" -ForegroundColor $ColorCyan
    Write-Host "│  To start one-command protection right now in PowerShell:              │" -ForegroundColor $ColorCyan
    Write-Host "│                                                                        │" -ForegroundColor $ColorCyan
    Write-Host "│    `$env:Path = `"$InstallDir;`$env:Path`"; agentcontrol protect           │" -ForegroundColor $ColorGreen
    Write-Host "│                                                                        │" -ForegroundColor $ColorCyan
    Write-Host "└────────────────────────────────────────────────────────────────────────┘" -ForegroundColor $ColorCyan
    Write-Host ""
}
