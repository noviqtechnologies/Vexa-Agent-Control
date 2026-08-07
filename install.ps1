<#
.SYNOPSIS
    AgentWall Binary Installer for Windows.
    Usage: irm https://vexasec.io/install.ps1 | iex
           .\install.ps1 -Token <OTET_TOKEN> [-HubUrl <URL>]
#>

param(
    [string]$Token = $env:AGENTWALL_TOKEN,
    [string]$HubUrl = $env:AGENTWALL_HUB_URL
)

& {
    $ErrorActionPreference = "Stop"

    # Force TLS 1.2 — required by GitHub. Windows PowerShell 5.1 defaults to TLS 1.0/1.1
    # which causes 'connection closed unexpectedly' errors when downloading from GitHub releases.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $ColorCyan = "Cyan"
    $ColorGreen = "Green"
    $ColorRed = "Red"
    $ColorYellow = "Yellow"

    Write-Host "=============================================" -ForegroundColor $ColorCyan
    Write-Host "          AgentWall Installer              " -ForegroundColor $ColorCyan
    Write-Host "=============================================" -ForegroundColor $ColorCyan

    $InstallDir = Join-Path $env:USERPROFILE ".local\bin"
    $Repo = "noviqtechnologies/agentwall"

    # 1. Detect Architecture
    # Asset filenames on GitHub use x86_64/aarch64, NOT amd64/arm64
    $ArchMap = @{
        "AMD64" = "x86_64"
        "ARM64" = "aarch64"
    }
    $ArchEnv = $env:PROCESSOR_ARCHITECTURE
    $ArchTarget = $ArchMap[$ArchEnv]

    if (-not $ArchTarget) {
        Write-Host "Unsupported Architecture: $ArchEnv" -ForegroundColor $ColorRed
        return
    }

    Write-Host "Platform detected: windows-$ArchTarget" -ForegroundColor $ColorGreen

    # 2. Fetch Latest Version
    Write-Host "Fetching latest release version..."
    try {
        # Use /releases?per_page=1 instead of /releases/latest so that
        # pre-release versions are included (latest only returns stable releases).
        $ReleaseArgs = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases?per_page=1"
        $LatestRelease = $ReleaseArgs[0].tag_name
    } catch {
        Write-Host "Failed to determine the latest release version." -ForegroundColor $ColorRed
        return
    }
    $Version = $LatestRelease.TrimStart("v")
    Write-Host "Latest version: $Version" -ForegroundColor $ColorGreen

    # 2b. Check currently installed version
    $FinalBinaryPath = Join-Path $InstallDir "agentwall.exe"
    $InstalledVersion = $null
    if (Test-Path $FinalBinaryPath) {
        try {
            $InstalledVersion = (& $FinalBinaryPath --version 2>$null) -replace '[^0-9.]', '' | Select-Object -First 1
        } catch { $InstalledVersion = $null }
    }

    if ($InstalledVersion -and $InstalledVersion -eq $Version) {
        Write-Host "`n[+] AgentWall v$Version is already up to date. Nothing to do." -ForegroundColor $ColorGreen
        return
    } elseif ($InstalledVersion) {
        Write-Host "Upgrading $InstalledVersion -> $Version..." -ForegroundColor $ColorCyan
    } else {
        Write-Host "Fresh install of AgentWall v$Version..." -ForegroundColor $ColorCyan
    }

    # Asset filename must include 'v' prefix and '.zip' extension to match GitHub release artifacts.
    # e.g. agentwall-v1.0.16-windows-x86_64.zip
    $AssetName = "agentwall-v$Version-windows-$ArchTarget.zip"
    $BaseUrl   = "https://github.com/$Repo/releases/download/v$Version"
    $AssetUrl  = "$BaseUrl/$AssetName"
    $ChecksumsUrl = "$BaseUrl/checksums.txt"

    # 3. Create Temp Dir
    $TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "AgentWallInstall"
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
        } catch {
            if ($i -eq $MaxRetries) {
                Write-Host "Download failed after $MaxRetries attempts: $_" -ForegroundColor $ColorRed
                return
            }
            Write-Host "Attempt $i failed, retrying in $($i * 2)s..." -ForegroundColor $ColorYellow
            Start-Sleep -Seconds ($i * 2)
        }
    }

    Write-Host "Downloading checksums..."
    try {
        Invoke-WebRequest -Uri $ChecksumsUrl -OutFile $ChecksumsPath -UseBasicParsing
    } catch {
        Write-Host "Warning: checksums.txt not found, skipping verification." -ForegroundColor $ColorYellow
    }

    # 5. Verify Checksum (against the ZIP file)
    if (Test-Path $ChecksumsPath) {
        Write-Host "Verifying checksum..."
        $ExpectedHashStr = (Get-Content $ChecksumsPath | Where-Object { $_ -match $AssetName })
        if ($ExpectedHashStr) {
            $ExpectedHash = ($ExpectedHashStr -split ' ')[0].Trim().ToUpper()
            $ActualHash   = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash
            if ($ExpectedHash -ne $ActualHash) {
                Write-Host "Checksum mismatch! Expected: $ExpectedHash, Got: $ActualHash" -ForegroundColor $ColorRed
                return
            }
            Write-Host "Checksum verified." -ForegroundColor $ColorGreen
        } else {
            Write-Host "No checksum entry found for $AssetName, skipping verification." -ForegroundColor $ColorYellow
        }
    }

    # 6. Extract ZIP
    Write-Host "Extracting archive..."
    $ExtractDir = Join-Path $TempDir "extracted"
    Expand-Archive -Path $ZipPath -DestinationPath $ExtractDir -Force

    # Locate the binary inside the archive (install.sh finds it at bin/agentwall)
    $ExtractedBinary = Get-ChildItem -Path $ExtractDir -Recurse -Filter "agentwall*" |
        Where-Object { -not $_.PSIsContainer } | Select-Object -First 1

    if (-not $ExtractedBinary) {
        Write-Host "Could not locate agentwall binary inside the extracted archive." -ForegroundColor $ColorRed
        return
    }

    # 7. Install — move into place and rename to agentwall.exe
    Write-Host "Installing to $InstallDir..."
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    }

    $FinalBinaryPath = Join-Path $InstallDir "agentwall.exe"
    Copy-Item -Path $ExtractedBinary.FullName -Destination $FinalBinaryPath -Force
    Write-Host "Installed as agentwall.exe" -ForegroundColor $ColorGreen

    # Install quickstart_agent.py script
    $QuickstartScript = Get-ChildItem -Path $ExtractDir -Recurse -Filter "quickstart_agent.py" | Select-Object -First 1
    $QuickstartTarget = Join-Path $InstallDir "quickstart_agent.py"
    if ($QuickstartScript) {
        Copy-Item -Path $QuickstartScript.FullName -Destination $QuickstartTarget -Force
        Write-Host "Installed quickstart_agent.py" -ForegroundColor $ColorGreen
    } else {
        try {
            $QuickstartUrl = "https://raw.githubusercontent.com/$Repo/v$Version/quickstart_agent.py"
            Invoke-WebRequest -Uri $QuickstartUrl -OutFile $QuickstartTarget -UseBasicParsing
            Write-Host "Installed quickstart_agent.py" -ForegroundColor $ColorGreen
        } catch { }
    }

    # 7. Update PATH
    $CurrentPath = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::User)
    if ($CurrentPath -notlike "*$InstallDir*") {
        $NewPath = "$InstallDir;$CurrentPath".Replace(";;", ";")
        [Environment]::SetEnvironmentVariable("PATH", $NewPath, [EnvironmentVariableTarget]::User)
        $env:Path = "$InstallDir;$env:Path"
        Write-Host "Added $InstallDir to your PATH. Restart your terminal." -ForegroundColor $ColorYellow
    }

    Remove-Item $TempDir -Recurse -Force | Out-Null

    # Automated Enterprise Enrollment & Windows SCM Service Registration
    if (-not $Token) { $Token = $env:AGENTWALL_ENROLLMENT_TOKEN }
    if (-not $HubUrl) { $HubUrl = "http://localhost:8400" }

    if ($Token) {
        Write-Host "`n[*] Initializing Enterprise Device Governance..." -ForegroundColor $ColorCyan
        Write-Host "[*] Step 1/3: PKI Device Enrollment..." -ForegroundColor $ColorCyan
        & $FinalBinaryPath enroll --token $Token --hub-url $HubUrl

        Write-Host "[*] Step 2/3: Installing Persistent Windows SCM Service Daemon..." -ForegroundColor $ColorCyan
        & $FinalBinaryPath service install --hub-url $HubUrl

        Write-Host "[*] Step 3/3: Auto-wrapping active IDE targets..." -ForegroundColor $ColorCyan
        & $FinalBinaryPath wrap --all
        Write-Host "`n[+] Automated Enterprise Provisioning Completed!" -ForegroundColor $ColorGreen
    }

    if ($InstalledVersion) {
        Write-Host "`n[+] AgentWall upgraded from $InstalledVersion to $Version successfully!" -ForegroundColor $ColorGreen
    } else {
        Write-Host "`n[+] AgentWall $Version installed successfully!" -ForegroundColor $ColorGreen
    }
    Write-Host "Get started by running:"
    Write-Host "  agentwall --version"
    Write-Host "  agentwall dev"
    Write-Host ""
    Write-Host "To run the demo test script (requires Python 3.8+):" -ForegroundColor $ColorCyan
    Write-Host "  python '$env:USERPROFILE\.local\bin\quickstart_agent.py'" -ForegroundColor $ColorCyan

    Write-Host "Note: If you encounter 'Windows Protected Your PC', click 'More info' -> 'Run anyway'." -ForegroundColor $ColorYellow
    Write-Host "Note: Open a new terminal window if 'agentwall' is not found immediately." -ForegroundColor $ColorYellow
}

