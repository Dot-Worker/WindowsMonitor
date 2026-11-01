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
    & python -m PyInstaller --onefile --console --noupx --name WindowsMonitor --log-level WARN --specpath $build --workpath (Join-Path $build 'work') --distpath (Join-Path $build 'out') --add-data ($collector + ':.') --add-data ($versionFile + ':.') $entry
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed' }
    $exe = Join-Path $build 'out\WindowsMonitor.exe'
    $smoke = Join-Path $build 'smoke'
    $savedPath = $env:PATH
    Push-Location -LiteralPath (Split-Path $exe)
    try {
        $env:PATH = "$env:SystemRoot\System32;$env:SystemRoot"
        $reported = & $exe --version
        if ($LASTEXITCODE -ne 0 -or $reported -ne "WindowsMonitor $version") { throw 'Packaged version check failed' }
        & $exe scan --state $smoke
        if ($LASTEXITCODE -ne 0) { throw 'Standalone EXE scan failed' }
    } finally {
        $env:PATH = $savedPath
        Pop-Location
    }
    & python -E -S -c "import json,sys; r=json.load(open(sys.argv[1],encoding='utf8')); assert r['monitorVersion']==sys.argv[2] and r['coverage']['tasks']['observed'] and 'security' in r" (Join-Path $smoke 'settings.json') $version
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath (Join-Path $smoke 'settings.html'))) { throw 'Standalone report verification failed' }
    Copy-Item -LiteralPath $exe -Destination (Join-Path $dist 'WindowsMonitor.exe') -Force
    Get-FileHash -LiteralPath (Join-Path $dist 'WindowsMonitor.exe') -Algorithm SHA256
} finally {
    $temp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
    $resolved = (Resolve-Path -LiteralPath $build).Path
    if ([IO.Path]::GetDirectoryName($resolved) -eq $temp -and [IO.Path]::GetFileName($resolved) -match '^WindowsMonitor-build-[0-9a-f]{32}$') {
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
