#!/usr/bin/env pwsh
<#
.SYNOPSIS
  ALLINAGENT — Dynamic-Path Windows Host & Docker Stack Watchdog.
  Respects `maintenance.lock`, probes health via `allinagent.ps1 health --json`,
  and triggers non-destructive self-healing (`allinagent.ps1 up`) when needed.
#>
param(
    [int]$MaxLockAgeSeconds = 5400
)

$ErrorActionPreference = 'Stop'

$AllInAgentRoot = if ($env:ALLINAGENT_ROOT -and (Test-Path -LiteralPath $env:ALLINAGENT_ROOT)) {
    (Resolve-Path -LiteralPath $env:ALLINAGENT_ROOT).Path
} else {
    (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

$DataDir = if ($env:ALLINAGENT_DATA_DIR) {
    $env:ALLINAGENT_DATA_DIR
} else {
    Join-Path $AllInAgentRoot 'data'
}

$MaintLock = Join-Path $DataDir 'maintenance\maintenance.lock'
if (Test-Path -LiteralPath $MaintLock) {
    $AgeSeconds = ((Get-Date) - (Get-Item -LiteralPath $MaintLock).LastWriteTime).TotalSeconds
    if ($AgeSeconds -lt $MaxLockAgeSeconds) {
        Write-Output "MAINTENANCE_LOCK_ACTIVE: skipping watchdog reconcile ($([int]$AgeSeconds)s)"
        exit 0
    }
}

$CliEntry = Join-Path $AllInAgentRoot 'allinagent.ps1'
if (-not (Test-Path -LiteralPath $CliEntry)) {
    Write-Error "[watchdog] Missing CLI wrapper at: $CliEntry"
    exit 1
}

$HealthRaw = (& $CliEntry health --json 2>$null) -join "`n"
$IsHealthy = $false
if ($HealthRaw -and $HealthRaw.Trim().StartsWith('{')) {
    try {
        $Parsed = $HealthRaw | ConvertFrom-Json
        $IsHealthy = [bool]$Parsed.ok
    } catch {
        $IsHealthy = $false
    }
}

if (-not $IsHealthy) {
    Write-Output "[watchdog] Degraded state detected; invoking non-destructive 'allinagent up'..."
    & $CliEntry up | Out-Null
    Start-Sleep -Seconds 10
    $null = & $CliEntry health --json 2>$null
}

exit 0
