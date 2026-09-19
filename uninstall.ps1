<#
.SYNOPSIS
    Compatibility wrapper for uninstall/uninstall.ps1
#>
param(
    [switch]$KeepConfig = $false
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$TargetScript = Join-Path $ScriptDir "uninstall\uninstall.ps1"

if (Test-Path $TargetScript) {
    if ($KeepConfig) {
        & $TargetScript -KeepConfig
    } else {
        & $TargetScript
    }
} else {
    $Params = if ($KeepConfig) { "-KeepConfig" } else { "" }
    Invoke-Expression "& { $(Invoke-RestMethod 'https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/uninstall/uninstall.ps1') } $Params"
}
