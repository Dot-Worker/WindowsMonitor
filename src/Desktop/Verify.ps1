param([Parameter(Mandatory=$true)][string]$Executable,[Parameter(Mandatory=$true)][string]$State,[string]$EntryScript)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes
Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class MonitorButtonTest{[DllImport("user32.dll")]public static extern IntPtr SendMessageTimeout(IntPtr hwnd,uint msg,IntPtr w,IntPtr l,uint flags,uint timeout,out IntPtr result);}'
Add-Type -TypeDefinition 'using System;using System.Runtime.InteropServices;public class MonitorCloseTest{[DllImport("user32.dll")]public static extern bool PostMessage(IntPtr hwnd,uint msg,IntPtr w,IntPtr l);}'
$env:WM_DESKTOP_TEST_STATE = $State
$null = [IO.Directory]::CreateDirectory($State)
$utf8 = [Text.UTF8Encoding]::new($false)
function SaveFixture($name,$data) {
    [IO.File]::WriteAllText((Join-Path $State $name),(ConvertTo-Json $data -Depth 12),$utf8)
}
function Until($action,$seconds=30) {
    $deadline = [DateTime]::UtcNow.AddSeconds($seconds)
    do {
        $result = & $action
        if ($result) { return $result }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Desktop test timed out: $action"
}
function LaunchClient {
    $arguments = 'ui --state "'+$State+'"'
    if ($EntryScript) { $arguments = '"'+$EntryScript+'" '+$arguments }
    $script:launcher = Start-Process -FilePath $Executable -ArgumentList $arguments -WindowStyle Hidden -PassThru
    $script:window = Until {
        $candidate = Get-CimInstance Win32_Process -Filter "Name='WindowsMonitor.Desktop.exe'" |
            Where-Object { $_.CommandLine -and $_.CommandLine.Contains($State) } | Select-Object -First 1
        if ($candidate) {
            $script:desktop = Get-Process -Id $candidate.ProcessId -ErrorAction SilentlyContinue
            if ($desktop -and $desktop.MainWindowHandle -ne [IntPtr]::Zero -and $desktop.MainWindowTitle -eq 'WindowsMonitor · 本机监控中心') {
                return [System.Windows.Automation.AutomationElement]::FromHandle($desktop.MainWindowHandle)
            }
        }
    }
    Write-Output "Desktop ready: pid $($desktop.Id), handle $($desktop.MainWindowHandle)"
}
function Element($name) {
    if (-not $desktop -or $desktop.HasExited) {throw "Test desktop exited before reading '$name'"}
    $desktop.Refresh()
    $script:window = [System.Windows.Automation.AutomationElement]::FromHandle($desktop.MainWindowHandle)
    $condition = [System.Windows.Automation.PropertyCondition]::new([System.Windows.Automation.AutomationElement]::NameProperty,$name)
    return $window.FindFirst([System.Windows.Automation.TreeScope]::Descendants,$condition)
}
function Click($name) {
    Write-Output "Checking button: $name"
    try { $control = Until { $button = Element $name; if ($button -and $button.Current.IsEnabled) { $button } } } catch {
        $names = @($window.FindAll([System.Windows.Automation.TreeScope]::Descendants,[System.Windows.Automation.Condition]::TrueCondition) |
            ForEach-Object {$_.Current.Name} | Where-Object {$_})
        throw "Button '$name' not found in test window. Visible controls: $($names -join ' | ')"
    }
    if (-not $control.Current.IsEnabled) {throw "Disabled test button: $name"}
    $result=[IntPtr]::Zero
    if ([MonitorButtonTest]::SendMessageTimeout([IntPtr]$control.Current.NativeWindowHandle,0xF5,[IntPtr]::Zero,[IntPtr]::Zero,2,3000,[ref]$result) -eq [IntPtr]::Zero) {throw "Button click failed: $name"}
}
function CloseClient {
    if ($desktop -and -not $desktop.HasExited) {
        $desktop.Refresh()
        $handle = $desktop.MainWindowHandle
        if ($window) { $handle = [IntPtr]$window.Current.NativeWindowHandle }
        if ($handle -eq [IntPtr]::Zero) { $handle = Until { $desktop.Refresh(); if ($desktop.MainWindowHandle -ne [IntPtr]::Zero) { $desktop.MainWindowHandle } } }
        $script:window = $null
        [GC]::Collect()
        if (-not [MonitorCloseTest]::PostMessage($handle,0x10,[IntPtr]::Zero,[IntPtr]::Zero)) { throw 'Unable to post WM_CLOSE to fixture' }
        $null = Until {$desktop.HasExited}
    }
    if ($launcher) { $null = Until {$launcher.HasExited} }
}
$report = @{time='2026-01-01T00:00:00Z'; shortcuts=@(); changes=@(); security=@{
    state=@{'模式'='关闭'}; events=@(@{id=1116;title='Desktop test detection';time='00:00'},@{id=1124;title='Audit only';time='00:01'})};
    coverage=@{fixture=@{errors=@{probe='test only'}}}}
SaveFixture 'settings.json' $report
$mock = $null
try {
    LaunchClient
    Click '高风险   1'
    $null = Until {Element '全部项目   /   1 项'}
    $null = Until {Element 'Desktop test detection'}
    Click '读取缺口'
    $null = Until {Element '读取缺口   /   1 项'}
    Click '扫描进程与模块'
    $null = Until {Test-Path -LiteralPath (Join-Path $State 'processes.json')} 240
    $baseline = (Get-Item -LiteralPath (Join-Path $State 'processes.json')).LastWriteTimeUtc
    $mock = [IO.File]::Open((Join-Path $State 'watch.lock'),'OpenOrCreate','ReadWrite','ReadWrite')
    $mock.Lock(0,1)
    SaveFixture 'watch.json' @{manualRequests=$true;elevated=$false}
    $null = Until { $b=Element '扫描进程与模块'; $b -and $b.Current.IsEnabled }
    Click '扫描进程与模块'
    $null = Until {Test-Path -LiteralPath (Join-Path $State 'processes.request')}
    Click '打开后自动监控'
    $null = Until {Test-Path -LiteralPath (Join-Path $State 'desktop.autostart')}
    Click '停止持续监控'
    $null = Until {Test-Path -LiteralPath (Join-Path $State 'stop.request')}
} finally {
    if ($mock) { $mock.Dispose() }
    CloseClient
}
Remove-Item -LiteralPath (Join-Path $State 'watch.json'),(Join-Path $State 'processes.request'),(Join-Path $State 'stop.request')
# Seed only the isolated UI fixture, so this test does not start a full Windows file pass.
$srcDir = Split-Path -Parent $PSScriptRoot
& python -E -S -c "import sys;sys.path.insert(0,sys.argv[1]);from monitor import database,now;db=database(sys.argv[2]);db.execute('INSERT INTO runs(job,stamp,version,report) VALUES(?,?,?,?)',('files',now(),'{}','{}'));db.commit();db.close()" $srcDir (Join-Path $State 'monitor.sqlite')
if ($LASTEXITCODE -ne 0) { throw 'Desktop fixture setup failed' }
try {
    LaunchClient
    $null = Until {Test-Path -LiteralPath (Join-Path $State 'watch.pid')}
    $null = Until {(Get-Item -LiteralPath (Join-Path $State 'processes.json')).LastWriteTimeUtc -gt $baseline} 240
    if ($desktop.HasExited) { throw "Auto-start desktop closed unexpectedly (exit $($desktop.ExitCode))" }
    CloseClient
    $pidText = [IO.File]::ReadAllText((Join-Path $State 'watch.pid'))
    if (-not (Get-Process -Id ([int]$pidText) -ErrorAction SilentlyContinue)) { throw 'Background did not survive UI close' }
} finally {
    if (Test-Path -LiteralPath (Join-Path $State 'watch.pid')) {
        [IO.File]::WriteAllText((Join-Path $State 'stop.request'),'stop')
        $null = Until {-not (Test-Path -LiteralPath (Join-Path $State 'watch.pid'))}
    }
    CloseClient
}
Write-Output 'Desktop checks passed: severity filter, evidence, manual request, persisted auto-start, live scan and stop.'
