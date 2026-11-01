param([Parameter(Mandatory=$true)][ValidatePattern('^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$')][string]$Version)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $root

function RunGit([string[]]$GitArgs) {
    & git @GitArgs
    if ($LASTEXITCODE -ne 0) { throw "git $($GitArgs[0]) failed ($LASTEXITCODE)" }
}

$branch = (RunGit @('symbolic-ref','--short','HEAD')).Trim()
$remote = & git config --get "branch.$branch.remote"
if (-not $remote) { $remote = 'origin' }
$dest = & git config --get "branch.$branch.merge"
if (-not $dest) { $dest = "refs/heads/$branch" }
if (-not $dest.StartsWith('refs/heads/')) { throw 'Unsupported upstream branch' }
$remoteUrl = (RunGit @('remote','get-url','--push',$remote)).Trim()
$before = ''
& git rev-parse --verify --quiet HEAD | Out-Null
if ($LASTEXITCODE -eq 0 -and (RunGit @('ls-tree','--name-only','HEAD','--','VERSION'))) {
    $before = (RunGit @('show','HEAD:VERSION')).Trim()
}

if ($Version -ne $before) {
    if ($before -and [Version]$Version -lt [Version]$before) { throw 'Choose a higher release version' }
    & python -E -S -X utf8 -m unittest discover -s src -v
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed; release stopped' }
    [IO.File]::WriteAllText((Join-Path $root 'VERSION'), $Version + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    & (Join-Path $PSScriptRoot 'Build.ps1')
    RunGit @('add','-u','--','.')
    RunGit @('add','--','VERSION','dist/WindowsMonitor.exe')
    $staged = @(RunGit @('diff','--cached','--name-only'))
    if ($staged -match '^\.windowsmonitor/|\.sqlite(?:-wal|-shm)?$|^__pycache__/') { throw 'Local monitor data staged; release stopped' }
    RunGit @('diff','--cached','--check')
    RunGit @('commit','-m',"Release v$Version")
} elseif (RunGit @('status','--porcelain','--untracked-files=no')) {
    throw 'Tracked files changed. Choose a new release version.'
}

$pushArgs = @()
# Respect explicit Git/env proxy settings first. Use the configured Windows HTTPS proxy otherwise.
if ($remoteUrl.StartsWith('https://') -and -not $env:HTTPS_PROXY -and -not $env:ALL_PROXY) {
    $explicit = & git config --get-urlmatch http.proxy $remoteUrl
    if ($LASTEXITCODE -ne 0) {
        $uri = [Uri]$remoteUrl
        $proxy = [Net.WebRequest]::DefaultWebProxy
        if ($proxy -and -not $proxy.IsBypassed($uri)) {
            $proxyUri = $proxy.GetProxy($uri)
            if ($proxyUri -and $proxyUri -ne $uri) { $pushArgs = @('-c',('http.proxy=' + $proxyUri.AbsoluteUri)) }
        }
    }
}
# A rejected/non-fast-forward push leaves the release commit available for retry.
RunGit ($pushArgs + @('push','-u',$remote,("HEAD:" + $dest)))
