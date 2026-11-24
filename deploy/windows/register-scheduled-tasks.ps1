#!/usr/bin/env pwsh
<#
.SYNOPSIS
  ALLINAGENT — Dynamic-Path Windows Task Scheduler Registration Helper.
  Registers `\ALLINAGENT\StackAutostart`, `\ALLINAGENT\HealthWatchdog`, and
  `\ALLINAGENT\DailyMaintenance` without hardcoded drive or user paths.
#>
param(
    [string]$DailyMaintenanceTime = '03:00:00',
    [switch]$Unregister
)

$ErrorActionPreference = 'Stop'

$AllInAgentRoot = if ($env:ALLINAGENT_ROOT -and (Test-Path -LiteralPath $env:ALLINAGENT_ROOT)) {
    (Resolve-Path -LiteralPath $env:ALLINAGENT_ROOT).Path
} else {
    (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
}

$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
$CliWrapper = Join-Path $AllInAgentRoot 'allinagent.ps1'
$WatchdogScript = Join-Path $AllInAgentRoot 'deploy\windows\platform-watchdog.ps1'

$Schedule = New-Object -ComObject 'Schedule.Service'
$Schedule.Connect()
$RootFolder = $Schedule.GetFolder('\')

if ($Unregister) {
    try {
        $Folder = $RootFolder.GetFolder('ALLINAGENT')
        foreach ($Task in $Folder.GetTasks(1)) {
            $Folder.DeleteTask($Task.Name, 0)
        }
        $RootFolder.DeleteFolder('ALLINAGENT', 0)
        Write-Output 'UNREGISTERED_ALLINAGENT_TASKS_OK'
    } catch {
        Write-Output 'NO_EXISTING_ALLINAGENT_TASKS'
    }
    exit 0
}

try {
    $Folder = $RootFolder.GetFolder('ALLINAGENT')
} catch {
    $Folder = $RootFolder.CreateFolder('ALLINAGENT')
}

$PwshCmd = if (Get-Command pwsh -ErrorAction SilentlyContinue) { 'pwsh.exe' } else { 'powershell.exe' }
$EscRoot = [System.Security.SecurityElement]::Escape($AllInAgentRoot)
$EscUser = [System.Security.SecurityElement]::Escape($CurrentUser)
$EscCli = [System.Security.SecurityElement]::Escape($CliWrapper)
$EscWatchdog = [System.Security.SecurityElement]::Escape($WatchdogScript)
$StartDate = (Get-Date -Format 'yyyy-MM-dd')

$AutostartXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>$EscUser</Author>
    <Description>ALLINAGENT Docker Compose Stack Autostart on Logon</Description>
    <URI>\ALLINAGENT\StackAutostart</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>$EscUser</UserId>
      <Delay>PT30S</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$EscUser</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <Enabled>true</Enabled>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$PwshCmd</Command>
      <Arguments>-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "$EscCli" up</Arguments>
      <WorkingDirectory>$EscRoot</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@

$WatchdogXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>$EscUser</Author>
    <Description>ALLINAGENT 15-Minute Self-Healing Health Watchdog</Description>
    <URI>\ALLINAGENT\HealthWatchdog</URI>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>PT15M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>${StartDate}T00:05:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$EscUser</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <Enabled>true</Enabled>
    <ExecutionTimeLimit>PT5M</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$PwshCmd</Command>
      <Arguments>-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "$EscWatchdog"</Arguments>
      <WorkingDirectory>$EscRoot</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@

$MaintenanceXml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>$EscUser</Author>
    <Description>ALLINAGENT Daily 03:00 Coordinated Safe Update &amp; DB Backup</Description>
    <URI>\ALLINAGENT\DailyMaintenance</URI>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>${StartDate}T${DailyMaintenanceTime}</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$EscUser</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <Enabled>true</Enabled>
    <ExecutionTimeLimit>PT30M</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$PwshCmd</Command>
      <Arguments>-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "$EscCli" update --scheduled-maintenance --yes</Arguments>
      <WorkingDirectory>$EscRoot</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@

$null = $Folder.RegisterTask('StackAutostart', $AutostartXml, 6, $CurrentUser, $null, 3, $null)
$null = $Folder.RegisterTask('HealthWatchdog', $WatchdogXml, 6, $CurrentUser, $null, 3, $null)
$null = $Folder.RegisterTask('DailyMaintenance', $MaintenanceXml, 6, $CurrentUser, $null, 3, $null)

Write-Output "REGISTERED_ALLINAGENT_TASKS_OK ($AllInAgentRoot)"
