<#
.SYNOPSIS
    Microsoft Intune / Endpoint Manager Deployment Script for Vexa Agent Control
.DESCRIPTION
    Installs, configures, and registers Vexa Agent Control as a managed Windows system service.
    Configures registry-based policy enforcement and system-level proxy variables for 
    AI coding assistants (Cursor, VS Code, Windsurf, Claude Desktop).
.PARAMETER HubUrl
    Central Vexa Team Hub / Control Plane API URL (e.g. https://agentcontrol.internal.corp)
.PARAMETER EnrollmentToken
    One-Time Enrollment Token (OTET) for device onboarding
.PARAMETER EnforcementMode
    Enforcement posture: 'shadow' (observe only), 'guard' (soft warnings), or 'enforced' (mandatory blocks)
.PARAMETER Uninstall
    If specified, cleanly removes service, policies, and binaries
#>
[CmdletBinding()]
param(
    [string]$HubUrl = "",
    [string]$EnrollmentToken = "",
    [ValidateSet("shadow", "guard", "enforced")]
    [string]$EnforcementMode = "shadow",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

$InstallDir = "$env:ProgramFiles\Vexa\AgentControl"
$ServiceName = "AgentControlService"
$BinName = "agentcontrol.exe"
$BinPath = Join-Path $InstallDir $BinName
$LogDir = "$env:ProgramData\Vexa\AgentControl\logs"
$PolicyRegKey = "HKLM:\SOFTWARE\Policies\Vexa\AgentControl"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "[$ts] [$Level] $Message"
}

if ($Uninstall) {
    Write-Log "Initiating Vexa Agent Control uninstallation..."
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-Log "Stopping and removing service $ServiceName..."
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        sc.exe delete $ServiceName | Out-Null
    }
    if (Test-Path $PolicyRegKey) {
        Remove-Item -Path $PolicyRegKey -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $InstallDir) {
        Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Log "Uninstallation complete."
    exit 0
}

Write-Log "=== Deploying Vexa Agent Control Enterprise Workstation Sentry ==="

# 1. Ensure Target Directories Exist
if (!(Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
if (!(Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# 2. Verify Binary Presence
if (!(Test-Path $BinPath)) {
    # If script is bundled with binary in Intunewin package:
    $SourceBin = Join-Path $PSScriptRoot $BinName
    if (Test-Path $SourceBin) {
        Copy-Item -Path $SourceBin -Destination $BinPath -Force
        Write-Log "Copied binary from package to $BinPath"
    } else {
        Write-Log "Downloading pinned release binary..."
        $DownloadUrl = "https://github.com/noviqtechnologies/Vexa-Agent-Control/releases/download/v1.0.95/agentcontrol-x86_64-pc-windows-msvc.zip"
        $ZipPath = Join-Path $env:TEMP "agentcontrol.zip"
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipPath -UseBasicParsing
        Expand-Archive -Path $ZipPath -DestinationPath $env:TEMP\agentcontrol_unpack -Force
        $Extracted = Get-ChildItem -Path "$env:TEMP\agentcontrol_unpack" -Recurse -Filter $BinName | Select-Object -First 1
        if ($Extracted) {
            Copy-Item -Path $Extracted.FullName -Destination $BinPath -Force
        } else {
            throw "Failed to locate $BinName in release archive."
        }
    }
}

# 3. Configure Enterprise Registry Policies
Write-Log "Configuring enterprise registry policy: EnforcementMode=$EnforcementMode"
if (!(Test-Path $PolicyRegKey)) {
    New-Item -ItemType Directory -Path $PolicyRegKey -Force | Out-Null
}
Set-ItemProperty -Path $PolicyRegKey -Name "EnforcementMode" -Value $EnforcementMode -Type String -Force
Set-ItemProperty -Path $PolicyRegKey -Name "InstalledVersion" -Value "1.0.95" -Type String -Force
Set-ItemProperty -Path $PolicyRegKey -Name "ManagedBy" -Value "Microsoft Intune" -Type String -Force

if ($HubUrl) {
    Set-ItemProperty -Path $PolicyRegKey -Name "HubUrl" -Value $HubUrl -Type String -Force
}

# 4. Configure Mandatory System Environment Variables
Write-Log "Configuring system-level proxy variables for loopback governance..."
[Environment]::SetEnvironmentVariable("AGENTCONTROL_GATEWAY_URL", "http://127.0.0.1:18080", "Machine")

# 5. Service Registration
Write-Log "Registering Windows Service: $ServiceName"
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

$ServiceArgs = "start --port 18080 --log-dir `"$LogDir`""
if ($EnforcementMode -eq "shadow") {
    $ServiceArgs += " --shadow"
}
if ($HubUrl -and $EnrollmentToken) {
    $ServiceArgs += " --hub `"$HubUrl`" --enroll-token `"$EnrollmentToken`""
}

$BinAndArgs = "`"$BinPath`" $ServiceArgs"
& sc.exe create $ServiceName binPath= $BinAndArgs start= auto DisplayName= "Vexa Agent Control Sentry" depend= Tcpip
& sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/60000

# 6. Start Service
Write-Log "Starting $ServiceName..."
Start-Service -Name $ServiceName
Start-Sleep -Seconds 3

$svc = Get-Service -Name $ServiceName
if ($svc.Status -eq "Running") {
    Write-Log "Vexa Agent Control Service is ACTIVE and RUNNING."
} else {
    Write-Log "Service status is $($svc.Status). Review logs in $LogDir" "WARN"
}

Write-Log "Deployment script completed successfully."
exit 0
