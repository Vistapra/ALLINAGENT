#!/usr/bin/env pwsh
$ErrorActionPreference = 'Stop'

$RepoRoot = (Resolve-Path $PSScriptRoot).Path
if (-not $env:ALLINAGENT_ROOT) {
    $env:ALLINAGENT_ROOT = $RepoRoot
}

$CliScript = Join-Path $RepoRoot 'scripts\allinagent_cli.py'
if (-not (Test-Path -LiteralPath $CliScript)) {
    Write-Error "[allinagent] Missing CLI script at: $CliScript"
    exit 1
}

$PythonCmd = $null
foreach ($cand in @('python', 'python3', 'py')) {
    $found = Get-Command $cand -ErrorAction SilentlyContinue
    if ($found) {
        $PythonCmd = $found.Source
        break
    }
}

if (-not $PythonCmd) {
    Write-Error '[allinagent] Python 3.10+ is required on PATH.'
    exit 1
}

if ([System.IO.Path]::GetFileNameWithoutExtension($PythonCmd).ToLowerInvariant() -eq 'py') {
    & $PythonCmd -3 $CliScript @args
} else {
    & $PythonCmd $CliScript @args
}
exit $LASTEXITCODE
