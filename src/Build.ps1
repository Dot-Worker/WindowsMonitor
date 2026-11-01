$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$version = [IO.File]::ReadAllText((Join-Path $root 'VERSION')).Trim()
$build = Join-Path ([IO.Path]::GetTempPath()) ('WindowsMonitor-build-' + [Guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($build)
$dist = Join-Path $root 'dist'
$null = [IO.Directory]::CreateDirectory($dist)
try {
    $collector = Join-Path $PSScriptRoot 'collect.ps1'
    $versionFile = Join-Path $root 'VERSION'
    $entry = Join-Path $PSScriptRoot 'monitor.py'
    $desktop = Join-Path $build 'WindowsMonitor.Desktop.exe'
    & (Join-Path $PSScriptRoot 'Desktop\Compile.ps1') -OutputFile $desktop
    & python -m PyInstaller --onefile --console --hide-console hide-early --noupx --name WindowsMonitor --log-level WARN --specpath $build --workpath (Join-Path $build 'work') --distpath (Join-Path $build 'out') --add-data ($collector + ':.') --add-data ($versionFile + ':.') --add-data ($desktop + ':.') $entry
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed' }
    $exe = Join-Path $build 'out\WindowsMonitor.exe'
    $smoke = Join-Path $build 'smoke'
    $savedPath = $env:PATH
    $savedLocal = $env:LOCALAPPDATA
    Push-Location -LiteralPath (Split-Path $exe)
    try {
        $env:PATH = "$env:SystemRoot\System32;$env:SystemRoot"
        $env:LOCALAPPDATA = Join-Path $build 'browser-fixture'
        $sample = Join-Path $env:LOCALAPPDATA ('Google\Chrome\User Data\Default\Extensions\' + ('a'*32) + '\1.0_0')
        $null = [IO.Directory]::CreateDirectory($sample)
        [IO.File]::WriteAllText((Join-Path $sample 'manifest.json'),'{"version":"1.0","permissions":["storage"]}')
        $reported = & $exe --version
        if ($LASTEXITCODE -ne 0 -or $reported -ne "WindowsMonitor $version") { throw 'Packaged version check failed' }
        & $exe scan --state $smoke
        if ($LASTEXITCODE -ne 0) { throw 'Standalone EXE scan failed' }
    } finally {
        $env:PATH = $savedPath
        $env:LOCALAPPDATA = $savedLocal
        Pop-Location
    }
    & python -E -S -c "import json,sys; r=json.load(open(sys.argv[1],encoding='utf8')); assert r['monitorVersion']==sys.argv[2] and r['coverage']['tasks']['observed'] and r['coverage']['browser-extensions']['observed']==1 and 'security' in r" (Join-Path $smoke 'settings.json') $version
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath (Join-Path $smoke 'settings.html'))) { throw 'Standalone report verification failed' }
    $shell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    & $shell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'Desktop\Verify.ps1') -Executable $exe -State (Join-Path $build 'desktop-smoke')
    if ($LASTEXITCODE -ne 0) { throw 'Packaged desktop verification failed' }
    $target = Join-Path $dist 'WindowsMonitor.exe'
    $stage = Join-Path $dist ([Guid]::NewGuid().ToString('N') + '.tmp')
    # Windows can retain a mapped executable until the old client exits. Give it
    # a name on the same volume outside dist, instead of a Windows-generated ~RF TMP in dist.
    $retired = Join-Path $root '.windowsmonitor\retired-builds'
    [void][IO.Directory]::CreateDirectory($retired)
    try {
        [IO.File]::Copy($exe, $stage)
        if ([IO.File]::Exists($target)) {
            $backup = Join-Path $retired ('retired-' + [Guid]::NewGuid().ToString('N') + '.old')
            [IO.File]::Replace($stage, $target, $backup)
        } else {
            [IO.File]::Move($stage, $target)
        }
    } finally {
        if ([IO.File]::Exists($stage)) { [IO.File]::Delete($stage) }
    }
    foreach ($old in Get-ChildItem -LiteralPath $retired -File -Filter 'retired-*.old') {
        if ($old.Name -match '^retired-[a-f0-9]{32}\.old$' -and -not ($old.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            try { [IO.File]::Delete($old.FullName) }
            catch [IO.IOException] { }  # The old process still has this image mapped.
            catch [UnauthorizedAccessException] { }
        }
    }
    Get-FileHash -LiteralPath $target -Algorithm SHA256
} finally {
    $temp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
    $resolved = (Resolve-Path -LiteralPath $build).Path
    if ([IO.Path]::GetDirectoryName($resolved) -eq $temp -and [IO.Path]::GetFileName($resolved) -match '^WindowsMonitor-build-[0-9a-f]{32}$') {
        try { Remove-Item -LiteralPath $resolved -Recurse -Force }
        catch { Write-Warning ("Temporary build directory is still in use: " + $resolved) }
    }
}
