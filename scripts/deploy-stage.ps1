<#
.SYNOPSIS
    High-Speed Parallel Build & Deployment Automation for AgentControl Stage on GCP.
.DESCRIPTION
    Builds container images concurrently using Cloud Build with e2-highcpu-8 workers
    and applies Terraform infrastructure with optimized parallelism (-parallelism=3 by default).
.PARAMETER SkipBuild
    Skips container image building and runs pure Terraform IaC apply (~20-30 seconds).
.PARAMETER AutoApprove
    Automatically approves the Terraform apply without interactive prompt.
.PARAMETER Parallelism
    Terraform parallelism concurrency (default 3).
.PARAMETER ProjectId
    GCP Project ID (defaults to GCP_PROJECT_ID env var, terraform.stage.tfvars, or gcloud config).
.EXAMPLE
    .\scripts\deploy-stage.ps1
    .\scripts\deploy-stage.ps1 -SkipBuild
    .\scripts\deploy-stage.ps1 -AutoApprove
    .\scripts\deploy-stage.ps1 -Parallelism 3
#>

[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [switch]$AutoApprove,
    [int]$Parallelism = 3,
    [string]$ProjectId = $env:GCP_PROJECT_ID
)

$ErrorActionPreference = "Stop"
$StartTime = Get-Date

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "  AgentControl Stage High-Speed Deployment Pipeline     " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
$InfraDir = "$RepoRoot\infra\gcp"

if (-not $ProjectId) {
    if (Test-Path "$InfraDir\terraform.stage.tfvars") {
        $ProjectId = (Get-Content "$InfraDir\terraform.stage.tfvars" | Where-Object { $_ -match '^\s*gcp_project_id\s*=\s*"([^"]+)"' } | ForEach-Object { $matches[1] })
    }
    if (-not $ProjectId) {
        $ProjectId = (& gcloud config get-value project 2>$null).Trim()
    }
}
if (-not $ProjectId) {
    Write-Error "GCP Project ID not found. Please set GCP_PROJECT_ID environment variable or pass -ProjectId."
}

$Region = "europe-west1"
$RepoId = "agentcontrol-stage"
$MachineType = "e2-highcpu-8"

function Get-DirSourceHash {
    param(
        [string[]]$Paths,
        [string[]]$ExtraFiles = @(),
        [string[]]$Excludes = @("node_modules", "dist", "vendor", ".log", ".git", "target", ".terraform")
    )
    $allHashes = @()
    foreach ($p in $Paths) {
        if (Test-Path $p) {
            $files = Get-ChildItem -Path $p -Recurse -File | Where-Object {
                $full = $_.FullName
                $skip = $false
                foreach ($ex in $Excludes) {
                    if ($full -like "*$ex*") {
                        $skip = $true
                        break
                    }
                }
                -not $skip
            } | Sort-Object FullName

            foreach ($f in $files) {
                $allHashes += (Get-FileHash -Path $f.FullName -Algorithm MD5).Hash
            }
        }
    }
    foreach ($ef in $ExtraFiles) {
        if (Test-Path $ef) {
            $allHashes += (Get-FileHash -Path $ef -Algorithm MD5).Hash
        }
    }

    $combined = $allHashes -join ""
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($combined)
    $hashBytes = $sha.ComputeHash($bytes)
    $hex = ($hashBytes | ForEach-Object { $_.ToString("x2") }) -join ""
    return $hex.Substring(0, 12).ToLower()
}

function Test-ImageExists {
    param([string]$ImageTag)
    $null = cmd /c "gcloud artifacts docker images describe $ImageTag --project=$ProjectId >nul 2>nul"
    return ($LASTEXITCODE -eq 0)
}

# 1. Verify GCP Authentication & Tools
Write-Host "`n[1/4] Verifying prerequisites..." -ForegroundColor Yellow
if (-not (Get-Command gcloud -ErrorAction SilentlyContinue)) {
    Write-Error "gcloud CLI not found. Please install Google Cloud SDK."
}
if (-not (Get-Command terraform -ErrorAction SilentlyContinue)) {
    Write-Error "terraform CLI not found. Please install Terraform."
}

# Calculate source hashes for deterministic tagging
$ApiHash = Get-DirSourceHash -Paths @("$RepoRoot\control-plane\api")
$UiHash = Get-DirSourceHash -Paths @("$RepoRoot\control-plane\ui")
$DbHash = Get-DirSourceHash -Paths @("$RepoRoot\control-plane\db")
$GwHash = Get-DirSourceHash -Paths @("$RepoRoot\src", "$RepoRoot\benches", "$RepoRoot\control-plane\proto", "$RepoRoot\keys") -ExtraFiles @("$RepoRoot\Cargo.toml", "$RepoRoot\Cargo.lock", "$RepoRoot\Dockerfile")

$BuildTargets = @(
    @{ Name = "Dashboard API"; Dir = "$RepoRoot\control-plane\api"; Image = "$Region-docker.pkg.dev/$ProjectId/$RepoId/dashboard-api:$ApiHash" },
    @{ Name = "Control Plane UI"; Dir = "$RepoRoot\control-plane\ui"; Image = "$Region-docker.pkg.dev/$ProjectId/$RepoId/control-plane-ui:$UiHash" },
    @{ Name = "Database"; Dir = "$RepoRoot\control-plane\db"; Image = "$Region-docker.pkg.dev/$ProjectId/$RepoId/agentcontrol-db:$DbHash" },
    @{ Name = "Gateway Proxy"; Dir = $RepoRoot; Image = "$Region-docker.pkg.dev/$ProjectId/$RepoId/agentcontrol-gateway:$GwHash" }
)

# 2. Build Container Images (if not skipped)
if (-not $SkipBuild) {
    Write-Host "`n[2/4] Checking image registry & submitting builds (Workers: $MachineType)..." -ForegroundColor Yellow

    $Jobs = @()
    foreach ($bt in $BuildTargets) {
        Write-Host -NoNewline "  * $($bt.Name): Checking Artifact Registry... " -ForegroundColor DarkGray
        if (Test-ImageExists -ImageTag $bt.Image) {
            Write-Host "[CACHED]" -ForegroundColor Green
        }
        else {
            Write-Host "[BUILDING IN CLOUD BUILD]" -ForegroundColor Cyan
            $jobName = "Build-$($bt.Name -replace ' ', '')"
            $Jobs += Start-Job -Name $jobName -ScriptBlock {
                param($Dir, $Tag, $Proj, $Reg, $Mach)
                Set-Location $Dir
                gcloud builds submit . --tag $Tag --project $Proj --region $Reg --machine-type $Mach --timeout=10m --quiet
                if ($LASTEXITCODE -ne 0) {
                    throw "Cloud Build failed with exit code $LASTEXITCODE"
                }
            } -ArgumentList $bt.Dir, $bt.Image, $ProjectId, $Region, $MachineType
        }
    }

    if ($Jobs.Count -gt 0) {
        Write-Host "`n  Waiting for $($Jobs.Count) parallel Cloud Build(s) to finish..." -ForegroundColor Yellow
        $spinIndex = 0
        $spinChars = @('|', '/', '-', '\')
        while (($Jobs | Where-Object { $_.State -eq "Running" }).Count -gt 0) {
            $runningCount = ($Jobs | Where-Object { $_.State -eq "Running" }).Count
            $completedCount = ($Jobs | Where-Object { $_.State -eq "Completed" }).Count
            $spinner = $spinChars[$spinIndex % 4]
            $spinIndex++
            Write-Host -NoNewline "`r  $spinner Cloud Build Progress: $completedCount/$($Jobs.Count) completed ($runningCount in progress)...   " -ForegroundColor Cyan
            Start-Sleep -Milliseconds 1000
        }
        Write-Host "`n"

        $HasError = $false
        foreach ($j in $Jobs) {
            $res = Receive-Job -Job $j -ErrorAction SilentlyContinue
            if ($j.State -ne "Completed") {
                Write-Host "  [FAIL] $($j.Name) failed!" -ForegroundColor Red
                if ($res) { Write-Host "    $res" -ForegroundColor DarkRed }
                $HasError = $true
            }
            else {
                Write-Host "  [OK] $($j.Name) finished successfully." -ForegroundColor Green
            }
        }
        $Jobs | Remove-Job

        if ($HasError) {
            Write-Error "One or more container builds failed. Aborting deployment."
        }
    }
    else {
        Write-Host "  All container images are up-to-date and cached in Artifact Registry." -ForegroundColor Green
    }
}
else {
    Write-Host "`n[2/4] Skipping container build step (-SkipBuild specified)." -ForegroundColor DarkGray
}

# 3. Apply Terraform Infrastructure
Write-Host "`n[3/4] Applying Terraform (Parallelism: $Parallelism)..." -ForegroundColor Yellow

$GcpHosts = @(
    "oauth2.googleapis.com",
    "iam.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    "artifactregistry.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "cloudbuild.googleapis.com"
)
foreach ($h in $GcpHosts) {
    $null = Resolve-DnsName -Name $h -Type A -ErrorAction SilentlyContinue
}

Push-Location $InfraDir
try {
    $TfArgs = @(
        "apply",
        "-var-file=terraform.stage.tfvars",
        "-var=container_image=$($BuildTargets[3].Image)",
        "-var=control_plane_api_image=$($BuildTargets[0].Image)",
        "-var=control_plane_ui_image=$($BuildTargets[1].Image)",
        "-var=control_plane_db_image=$($BuildTargets[2].Image)",
        "-parallelism=$Parallelism"
    )
    if ($AutoApprove) {
        $TfArgs += "-auto-approve"
    }

    $MaxAttempts = 3
    $Attempt = 1
    $Success = $false

    while ($Attempt -le $MaxAttempts -and -not $Success) {
        if ($Attempt -gt 1) {
            Write-Host "`n[Notice] Transient failure detected. Refreshing DNS cache and retrying ($Attempt/$MaxAttempts)..." -ForegroundColor Yellow
            $null = Clear-DnsClientCache
            foreach ($h in $GcpHosts) {
                $null = Resolve-DnsName -Name $h -Type A -ErrorAction SilentlyContinue
            }
            Start-Sleep -Seconds 2
        }

        & terraform @TfArgs
        if ($LASTEXITCODE -eq 0) {
            $Success = $true
        } else {
            $Attempt++
        }
    }

    if (-not $Success) {
        Write-Error "Terraform apply failed after $MaxAttempts attempt(s)."
        exit 1
    }

    # 4. Completion Summary
    $ElapsedTime = (Get-Date) - $StartTime
    $Min = [int]$ElapsedTime.TotalMinutes
    $Sec = [int]$ElapsedTime.Seconds
    Write-Host "`n========================================================" -ForegroundColor Green
    Write-Host "  Deployment successfully completed in $($Min)m $($Sec)s!  " -ForegroundColor Green
    Write-Host "========================================================" -ForegroundColor Green
} finally {
    Pop-Location
}
