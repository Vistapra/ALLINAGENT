#!/usr/bin/env pwsh
<#
.SYNOPSIS
  ALLINAGENT — Zero-Domain Encrypted SSH Loopback Tunnel (Windows PowerShell).
  Forwards remote 127.0.0.1:8200-8202 securely to local 127.0.0.1:8200-8202.
#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$RemoteTarget,
    [int]$SshPort = 22,
    [int]$LocalOfficePort = 8200,
    [int]$LocalPaperclipPort = 8201,
    [int]$LocalBridgePort = 8202,
    [int]$RemoteOfficePort = 8200,
    [int]$RemotePaperclipPort = 8201,
    [int]$RemoteBridgePort = 8202,
    [string]$IdentityFile = ""
)

$ErrorActionPreference = 'Stop'

Write-Host "======================================================================"
Write-Host " ALLINAGENT Secure SSH Loopback Tunnel"
Write-Host "   Remote Host         : $RemoteTarget (port $SshPort)"
Write-Host "   3D & 2D Office URL  : http://127.0.0.1:$LocalOfficePort/office"
Write-Host "   Paperclip API       : http://127.0.0.1:$LocalPaperclipPort/api/health"
Write-Host "   Office Bridge       : http://127.0.0.1:$LocalBridgePort/health"
Write-Host " Press Ctrl+C to close tunnel."
Write-Host "======================================================================"

$SshArgs = @(
    '-N',
    '-p', "$SshPort",
    '-o', 'ExitOnForwardFailure=yes',
    '-o', 'ServerAliveInterval=30',
    '-o', 'ServerAliveCountMax=3',
    '-L', "127.0.0.1:${LocalOfficePort}:127.0.0.1:${RemoteOfficePort}",
    '-L', "127.0.0.1:${LocalPaperclipPort}:127.0.0.1:${RemotePaperclipPort}",
    '-L', "127.0.0.1:${LocalBridgePort}:127.0.0.1:${RemoteBridgePort}"
)

if ($IdentityFile -and (Test-Path -LiteralPath $IdentityFile)) {
    $SshArgs += @('-i', $IdentityFile)
}

$SshArgs += $RemoteTarget
& ssh @SshArgs
exit $LASTEXITCODE
