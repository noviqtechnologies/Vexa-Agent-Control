<#
.SYNOPSIS
    Vexa Agent Control Binary Uninstaller for Windows.
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
    Write-Host "    Vexa Agent Control Clean Uninstaller     " -ForegroundColor $ColorCyan
    Write-Host "=============================================" -ForegroundColor $ColorCyan

    $InstallDir = Join-Path $env:USERPROFILE ".local\bin"
    $AgentControlBin = Join-Path $InstallDir "agentcontrol.exe"
    $LegacyBin = Join-Path $InstallDir "agentwall.exe"
    $ActiveBin = if (Test-Path $AgentControlBin) { $AgentControlBin } elseif (Test-Path $LegacyBin) { $LegacyBin } else { $null }

    # Step 1: Unprotect all IDE targets (restore original MCP configurations from backups)
    if ($ActiveBin -and (Test-Path $ActiveBin)) {
        Write-Host "[*] Step 1/4: Restoring original MCP configurations across all IDEs..." -ForegroundColor $ColorCyan
        try {
            & $ActiveBin unprotect --force 2>$null
        } catch {
            Write-Host "[!] Notice: IDE unprotect skipped or completed with warnings." -ForegroundColor $ColorYellow
        }
    } else {
        Write-Host "[!] Notice: Binary not found; skipping IDE unprotect." -ForegroundColor $ColorYellow
    }

    # Step 2: Stop and uninstall persistent Windows SCM Service Daemon
    Write-Host "[*] Step 2/4: Stopping and removing Windows Service..." -ForegroundColor $ColorCyan
    if ($ActiveBin -and (Test-Path $ActiveBin)) {
        try {
            & $ActiveBin service uninstall 2>$null
        } catch { }
    }

    # Fallback check using Windows Service Controller (sc.exe)
    foreach ($ServiceName in @("AgentControlSentry", "AgentWallSentry", "agentwall-sentry")) {
        $Svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($Svc) {
            Write-Host "[*] Cleaning remaining service registration for $ServiceName via sc.exe..." -ForegroundColor $ColorYellow
            try {
                sc.exe stop $ServiceName 2>$null | Out-Null
                sc.exe delete $ServiceName 2>$null | Out-Null
            } catch { }
        }
    }

    # Step 3: Remove binary executables
    Write-Host "[*] Step 3/4: Removing binary executables..." -ForegroundColor $ColorCyan
    $FilesToRemove = @(
        $AgentControlBin,
        $LegacyBin,
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

    # Step 4: Purge local configuration, logs, and PKI credentials (unless -KeepConfig specified)
    if (-not $KeepConfig) {
        Write-Host "[*] Step 4/4: Purging configuration, logs, and credentials..." -ForegroundColor $ColorCyan
        foreach ($dirName in @(".agentcontrol", ".agent-control", ".agentwall")) {
            $ConfigDir = Join-Path $env:USERPROFILE $dirName
            if (Test-Path $ConfigDir) {
                try {
                    Remove-Item -Path $ConfigDir -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Host "  [OK] Purged: $ConfigDir" -ForegroundColor $ColorGreen
                } catch {
                    Write-Host "  [!] Failed to purge: $ConfigDir" -ForegroundColor $ColorRed
                }
            }
        }
    }

    Write-Host "`n[+] Vexa Agent Control has been cleanly uninstalled from your system." -ForegroundColor $ColorGreen
}
