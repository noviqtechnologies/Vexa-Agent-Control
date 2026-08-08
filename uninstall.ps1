<#
.SYNOPSIS
    AgentWall Binary Uninstaller for Windows.
    Usage: .\uninstall.ps1 [-KeepConfig]
#>

param(
    [switch]$KeepConfig = $false
)

& {
    $ErrorActionPreference = "Continue"

    $ColorCyan = "Cyan"
    $ColorGreen = "Green"
    $ColorRed = "Red"
    $ColorYellow = "Yellow"

    Write-Host "=============================================" -ForegroundColor $ColorCyan
    Write-Host "        AgentWall Clean Uninstaller         " -ForegroundColor $ColorCyan
    Write-Host "=============================================" -ForegroundColor $ColorCyan

    $InstallDir = Join-Path $env:USERPROFILE ".local\bin"
    $FinalBinaryPath = Join-Path $InstallDir "agentwall.exe"

    # Step 1: Unwrap all IDE targets (restore original MCP configurations)
    if (Test-Path $FinalBinaryPath) {
        Write-Host "[*] Step 1/4: Unwrapping MCP servers across all IDEs..." -ForegroundColor $ColorCyan
        try {
            & $FinalBinaryPath unwrap --all 2>$null
        } catch {
            Write-Host "[!] Notice: IDE unwrap skipped or completed with warnings." -ForegroundColor $ColorYellow
        }
    } else {
        Write-Host "[!] Notice: AgentWall binary not found at $FinalBinaryPath; skipping IDE unwrap." -ForegroundColor $ColorYellow
    }

    # Step 2: Stop and uninstall persistent Windows SCM Service Daemon
    Write-Host "[*] Step 2/4: Stopping and removing Windows Service..." -ForegroundColor $ColorCyan
    if (Test-Path $FinalBinaryPath) {
        try {
            & $FinalBinaryPath service uninstall 2>$null
        } catch { }
    }

    # Fallback check using Windows Service Controller (sc.exe)
    $ServiceName = "AgentWallSentry"
    $Svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($Svc) {
        Write-Host "[*] Cleaning remaining service registration via sc.exe..." -ForegroundColor $ColorYellow
        try {
            sc.exe stop $ServiceName 2>$null | Out-Null
            sc.exe delete $ServiceName 2>$null | Out-Null
        } catch { }
    }

    # Step 3: Remove binary executables
    Write-Host "[*] Step 3/4: Removing binary executables..." -ForegroundColor $ColorCyan
    $FilesToRemove = @(
        (Join-Path $InstallDir "agentwall.exe"),
        (Join-Path $InstallDir "quickstart_agent.py")
    )

    foreach ($file in $FilesToRemove) {
        if (Test-Path $file) {
            try {
                Remove-Item -Path $file -Force -ErrorAction SilentlyContinue
                Write-Host "  [OK] Deleted: $file" -ForegroundColor $ColorGreen
            } catch {
                Write-Host "  [!] Failed to delete: $file" -ForegroundColor $ColorRed
            }
        }
    }

    # Step 4: Purge local configuration and PKI credentials (unless -KeepConfig specified)
    if (-not $KeepConfig) {
        Write-Host "[*] Step 4/4: Purging configuration and credentials..." -ForegroundColor $ColorCyan
        $ConfigDir = Join-Path $env:USERPROFILE ".agentwall"
        if (Test-Path $ConfigDir) {
            try {
                Remove-Item -Path $ConfigDir -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "  [OK] Purged configuration directory: $ConfigDir" -ForegroundColor $ColorGreen
            } catch {
                Write-Host "  [!] Failed to remove config directory: $ConfigDir" -ForegroundColor $ColorRed
            }
        }
    } else {
        Write-Host "[*] Skipping configuration purge (-KeepConfig flag set)." -ForegroundColor $ColorYellow
    }

    Write-Host "`n[OK] AgentWall has been cleanly uninstalled from this device!" -ForegroundColor $ColorGreen
}
