param([ValidateSet('Start','Status','Stop','AdminStart','EnableLogon','DisableLogon')][string]$Action='Status')
$ErrorActionPreference = 'Stop'
$state = Join-Path $PSScriptRoot '.windowsmonitor'
$scriptPath = Join-Path $PSScriptRoot 'monitor.py'
$taskName = 'WindowsMonitor-' + [Security.Principal.WindowsIdentity]::GetCurrent().User.Value

function WatchPid {
    $file = Join-Path $state 'watch.pid'
    if (-not [IO.File]::Exists($file)) { return }
    $watchId = [int](Get-Content -LiteralPath $file -Raw)
    $record = Get-CimInstance Win32_Process -Filter "ProcessId=$watchId"
    if ($record -and $record.CommandLine -and $record.CommandLine.IndexOf($scriptPath, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
        $record.CommandLine -match '\bwatch\b') { return $watchId }
    # A non-elevated status check cannot read an elevated command line.
    if ($record -and -not $record.CommandLine -and $record.Name -in 'python.exe','pythonw.exe') {
        $lockFile = Join-Path $state 'watch.lock'
        try {
            $test = [IO.File]::Open($lockFile, 'Open', 'ReadWrite', 'ReadWrite')
            try { $test.Lock(0,1); $test.Unlock(0,1) } finally { $test.Dispose() }
        } catch [IO.IOException] { return $watchId }
    }
}

switch ($Action) {
    Start {
        $running = WatchPid
        if ($running) { Write-Output "Already running: $running"; return }
        $null = [IO.Directory]::CreateDirectory($state)
        $python = (Get-Command python.exe).Source
        $process = Start-Process -WindowStyle Hidden -FilePath $python -ArgumentList ('-E -S -u -X utf8 "' + $scriptPath + '" watch') -PassThru -RedirectStandardOutput (Join-Path $state 'watch.log') -RedirectStandardError (Join-Path $state 'watch-error.log')
        for ($i=0; $i -lt 30; $i++) {
            if ($process.HasExited) { throw "Watcher exited. See $state\watch-error.log" }
            if ([IO.File]::Exists((Join-Path $state 'watch.pid')) -and [int](Get-Content (Join-Path $state 'watch.pid') -Raw) -eq $process.Id) {
                Write-Output "WindowsMonitor started: $($process.Id)"
                return
            }
            Start-Sleep -Milliseconds 200
        }
        throw "Watcher did not initialize. See $state\watch-error.log"
    }
    Status {
        $running = WatchPid
        if ($running) { Write-Output "Running: $running" } else { Write-Output 'Stopped' }
    }
    AdminStart {
        if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Start this action in an elevated PowerShell.' }
        & $PSCommandPath Stop
        & $PSCommandPath Start
    }
    Stop {
        $running = WatchPid
        if (-not $running) { Write-Output 'Stopped'; return }
        [IO.File]::WriteAllText((Join-Path $state 'stop.request'),'stop')
        for ($i=0; $i -lt 100; $i++) {
            if (-not [IO.File]::Exists((Join-Path $state 'watch.pid'))) { Write-Output 'Stopped'; return }
            Start-Sleep -Milliseconds 200
        }
        throw 'Watcher did not stop within 20 seconds'
    }
    EnableLogon {
        $user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        $pythonw = Join-Path (Split-Path (Get-Command python.exe).Source) 'pythonw.exe'
        $actionSpec = New-ScheduledTaskAction -Execute $pythonw -Argument ('"' + $scriptPath + '" watch')
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
        Register-ScheduledTask -TaskName $taskName -Action $actionSpec -Trigger $trigger -Settings $settings -User $user -RunLevel Limited -Description 'Start the read-only WindowsMonitor watcher at user logon.'
    }
    DisableLogon {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
}
