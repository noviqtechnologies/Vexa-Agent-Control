<#
.SYNOPSIS
    Vexa Agent Control - Runtime Enforcement Pilot Master Runner (PowerShell)
.DESCRIPTION
    Unified entrypoint that dispatches to the dedicated OS-specific pilot script:
      - Windows: scripts/run-pilot-windows.ps1
      - Linux:   scripts/run-pilot-linux.sh
      - macOS:   scripts/run-pilot-macos.sh
    Results are saved into unique datetime folders under result/<os>/<yyyyMMdd_HHmmss>/
    with ZERO duplicate files.
#>

[CmdletBinding()]
param(
    [ValidateSet('windows', 'linux', 'macos', 'all', 'auto')]
    [string]$Os = 'auto',
    [switch]$Detailed = $false
)

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Detect current host OS
$detectedOs = if ($IsWindows -or ($env:OS -like "*Windows*")) {
    "windows"
} elseif ($IsMacOS) {
    "macos"
} elseif ($IsLinux) {
    "linux"
} else {
    "windows"
}

$targetOsList = if ($Os -eq 'all') {
    @('windows', 'linux', 'macos')
} elseif ($Os -eq 'auto') {
    @($detectedOs)
} else {
    @($Os)
}

Write-Host '=================================================================' -ForegroundColor Cyan
Write-Host '  VEXA AGENT CONTROL - PILOT PLAN OS DISPATCHER                  ' -ForegroundColor Cyan
Write-Host '=================================================================' -ForegroundColor Cyan
Write-Host ('Detected Host: ' + $detectedOs) -ForegroundColor Gray
Write-Host ('Target OSes:   ' + ($targetOsList -join ', ')) -ForegroundColor Gray
Write-Host ''

# Locate Git Bash if on Windows for POSIX scripts
$gitBash = if (Test-Path 'C:\Program Files\Git\bin\bash.exe') {
    'C:\Program Files\Git\bin\bash.exe'
} elseif (Get-Command bash -ErrorAction SilentlyContinue) {
    'bash'
} else {
    $null
}

foreach ($target in $targetOsList) {
    Write-Host ('>> Executing dedicated pilot script for: ' + $target) -ForegroundColor Yellow
    switch ($target) {
        'windows' {
            $winScript = Join-Path $scriptDir "run-pilot-windows.ps1"
            $params = @{}
            if ($Detailed) { $params['Detailed'] = $true }
            & $winScript @params
        }
        'linux' {
            $linuxScript = Join-Path $scriptDir "run-pilot-linux.sh"
            if ($gitBash) {
                $argsList = @($linuxScript)
                if ($Detailed) { $argsList += '--detailed' }
                & $gitBash @argsList
            } else {
                Write-Host ('[SKIP] bash not found to execute Linux runner: ' + $linuxScript) -ForegroundColor DarkYellow
            }
        }
        'macos' {
            $macScript = Join-Path $scriptDir "run-pilot-macos.sh"
            if ($gitBash) {
                $argsList = @($macScript)
                if ($Detailed) { $argsList += '--detailed' }
                & $gitBash @argsList
            } else {
                Write-Host ('[SKIP] bash not found to execute macOS runner: ' + $macScript) -ForegroundColor DarkYellow
            }
        }
    }
}
