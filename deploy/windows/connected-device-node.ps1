#!/usr/bin/env pwsh
<#
.SYNOPSIS
  ALLINAGENT — Connected Windows Device & Workspace Companion Helper.
  Validates dynamic paths and opens an encrypted SSH loopback bridge to a
  remote Linux ALLINAGENT server or verifies a local Windows Docker instance.
#>
param(
    [string]$RemoteSshTarget = '',
    [int]$SshPort = 22,
    [switch]$StatusOnly
)

$ErrorActionPreference = 'Stop'

$AllInAgentRoot = if ($env:ALLINAGENT_ROOT -and (Test-Path -LiteralPath $env:ALLINAGENT_ROOT)) {
    (Resolve-Path -LiteralPath $env:ALLINAGENT_ROOT).Path
} else {
    (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

$TunnelScript = Join-Path $AllInAgentRoot 'deploy\proxy\ssh-tunnel-access.ps1'
$CliWrapper = Join-Path $AllInAgentRoot 'allinagent.ps1'

if ($StatusOnly) {
    & $CliWrapper doctor --json
    exit $LASTEXITCODE
}

if ($RemoteSshTarget) {
    & $TunnelScript -RemoteTarget $RemoteSshTarget -SshPort $SshPort
    exit $LASTEXITCODE
}

& $CliWrapper status
exit $LASTEXITCODE
