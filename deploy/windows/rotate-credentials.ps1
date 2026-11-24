#!/usr/bin/env pwsh
<#
.SYNOPSIS
  ALLINAGENT — Masked Credential Fingerprint & Safe Rotation Utility.
  Never prints raw secrets to stdout, logs, or process command lines.
#>
param(
    [ValidateSet('status', 'provider', 'telegram', 'internal-secrets')]
    [string]$Target = 'status'
)

$ErrorActionPreference = 'Stop'

$AllInAgentRoot = if ($env:ALLINAGENT_ROOT -and (Test-Path -LiteralPath $env:ALLINAGENT_ROOT)) {
    (Resolve-Path -LiteralPath $env:ALLINAGENT_ROOT).Path
} else {
    (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

$EnvFile = Join-Path $AllInAgentRoot '.env'
$CliWrapper = Join-Path $AllInAgentRoot 'allinagent.ps1'

function Get-SecretFingerprint([string]$Value) {
    if (-not $Value -or -not $Value.Trim()) { return 'UNSET' }
    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Value.Trim())
    $Sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $Hash = ($Sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
        return "sha256:$($Hash.Substring(0, 12))"
    } finally {
        $Sha.Dispose()
    }
}

function Read-DotEnvMap([string]$FilePath) {
    $Map = [ordered]@{}
    if (Test-Path -LiteralPath $FilePath) {
        foreach ($Line in (Get-Content -LiteralPath $FilePath -Encoding UTF8)) {
            if ($Line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$') {
                $Map[$Matches[1]] = $Matches[2].Trim().Trim('"').Trim("'")
            }
        }
    }
    return $Map
}

function Update-DotEnvKey([string]$FilePath, [string]$Key, [string]$NewValue) {
    $Lines = if (Test-Path -LiteralPath $FilePath) {
        [System.Collections.Generic.List[string]](Get-Content -LiteralPath $FilePath -Encoding UTF8)
    } else {
        New-Object 'System.Collections.Generic.List[string]'
    }
    $Updated = $false
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match "^\s*${Key}\s*=") {
            $Lines[$i] = "${Key}=${NewValue}"
            $Updated = $true
        }
    }
    if (-not $Updated) {
        $Lines.Add("${Key}=${NewValue}")
    }
    [System.IO.File]::WriteAllLines($FilePath, $Lines, (New-Object System.Text.UTF8Encoding($false)))
}

if ($Target -eq 'status') {
    $Map = Read-DotEnvMap $EnvFile
    [ordered]@{
        root_directory                = $AllInAgentRoot
        provider_api_key_fp           = Get-SecretFingerprint $Map['CUSTOM_API_KEY']
        telegram_bot_token_fp         = Get-SecretFingerprint $Map['TELEGRAM_BOT_TOKEN']
        studio_access_token_fp        = Get-SecretFingerprint $Map['STUDIO_ACCESS_TOKEN']
        office_bridge_token_fp        = Get-SecretFingerprint $Map['OFFICE_BRIDGE_TOKEN']
        paperclip_auth_secret_fp      = Get-SecretFingerprint $Map['BETTER_AUTH_SECRET']
        hermes_exec_shared_secret_fp  = Get-SecretFingerprint $Map['HERMES_EXEC_SHARED_SECRET']
    } | ConvertTo-Json -Depth 3
    exit 0
}

if ($Target -eq 'internal-secrets') {
    & $CliWrapper setup --yes --rotate-secrets --config-only
    exit $LASTEXITCODE
}

$PromptLabel = if ($Target -eq 'provider') { 'Enter new LLM Provider API Key (masked)' } else { 'Enter new Telegram Bot Token (masked)' }
$TargetKey = if ($Target -eq 'provider') { 'CUSTOM_API_KEY' } else { 'TELEGRAM_BOT_TOKEN' }

$Secure = Read-Host $PromptLabel -AsSecureString
$Bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
try {
    $Plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($Bstr).Trim()
    if ($Plain.Length -lt 10) {
        throw 'Credential length too short; rotation aborted.'
    }
    Update-DotEnvKey -FilePath $EnvFile -Key $TargetKey -NewValue $Plain
    & $CliWrapper setup --yes --config-only | Out-Null
    Write-Output "ROTATED_${TargetKey}_OK ($(Get-SecretFingerprint $Plain))"
} finally {
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr)
}
