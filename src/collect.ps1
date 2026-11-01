param([Parameter(Mandatory=$true)][string]$Section)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$env:PSModulePath = "$PSHOME\Modules;$env:ProgramFiles\WindowsPowerShell\Modules"
$WarningPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)

function Emit($key, $value) {
    [Console]::WriteLine((ConvertTo-Json -InputObject @{key=$key; value=$value} -Compress -Depth 16))
}
function Gap($key, $reason) {
    [Console]::WriteLine((ConvertTo-Json -InputObject @{key=$key; error=[string]$reason} -Compress))
}
function FileHash($path) {
    $stream = [IO.File]::OpenRead($path)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','') }
    finally { $sha.Dispose(); $stream.Dispose() }
}
function TaskFolder($folder) {
    try {
        foreach ($task in $folder.GetTasks(1)) {
            try { Emit $task.Path @{enabled=$task.Enabled; xml=$task.Xml} } catch { Gap $task.Path $_ }
        }
        foreach ($child in $folder.GetFolders(0)) { TaskFolder $child }
    } catch { Gap $folder.Path $_ }
}
function PolicyFiles($dir) {
    try {
        if (-not (Test-Path -LiteralPath $dir)) { return }
        if ([IO.File]::GetAttributes($dir) -band [IO.FileAttributes]::ReparsePoint) {
            Gap $dir 'reparse point excluded'
            return
        }
        foreach ($entry in Get-ChildItem -LiteralPath $dir -Force) {
            try {
                if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                    Gap $entry.FullName 'reparse point excluded'
                } elseif ($entry.PSIsContainer) {
                    PolicyFiles $entry.FullName
                } else {
                    Emit $entry.FullName @{sha256=(FileHash $entry.FullName)}
                }
            } catch { Gap $entry.FullName $_ }
        }
    } catch { Gap $dir $_ }
}
function Firewall {
    $fw = New-Object -ComObject HNetCfg.FwPolicy2
    foreach ($p in 1,2,4) {
        $key = "profile\$p"
        try {
            Emit $key @{enabled=$fw.FirewallEnabled($p); defaultIn=$fw.DefaultInboundAction($p);
                defaultOut=$fw.DefaultOutboundAction($p); blockInbound=$fw.BlockAllInboundTraffic($p);
                notificationsOff=$fw.NotificationsDisabled($p); excludedInterfaces=@($fw.ExcludedInterfaces($p) | Sort-Object)}
        } catch { Gap $key $_ }
    }
    # Registry rule IDs disambiguate duplicate display names.
    foreach ($path in 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy',
                      'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall') {
        if (-not (Test-Path -LiteralPath $path)) { continue }
        foreach ($k in (@(Get-Item -LiteralPath $path) + @(Get-ChildItem -LiteralPath $path -Recurse))) {
            foreach ($n in $k.GetValueNames()) { Emit ($k.Name + '\' + $n) ($k.GetValue($n)) }
        }
    }
    # The COM collection includes effective rules from multiple policy stores.
    $groups = @{}
    foreach ($r in $fw.Rules) {
        $k = 'effective\' + $r.Name
        if (-not $groups.ContainsKey($k)) { $groups[$k] = New-Object 'System.Collections.Generic.List[string]' }
        $fields = [ordered]@{}
        foreach ($field in 'ApplicationName','ServiceName','Protocol','LocalPorts','RemotePorts','IcmpTypesAndCodes',
                          'LocalAddresses','RemoteAddresses','Direction','Interfaces','InterfaceTypes','Enabled','Profiles',
                          'EdgeTraversal','Action','Grouping') { $fields[$field] = $r.$field }
        $groups[$k].Add((ConvertTo-Json $fields -Compress))
    }
    foreach ($k in $groups.Keys) { Emit $k @($groups[$k] | Sort-Object) }
}
function Defender {
    $pref = Get-MpPreference
    foreach ($p in $pref.CimInstanceProperties) {
        if ($p.Name -in 'ComputerID','PSComputerName') { continue }
        Emit ('preference\' + $p.Name) $p.Value
    }
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) { Gap 'exclusionVisibility' 'Non-elevated: exclusion lists may be hidden' }
    $status = Get-MpComputerStatus
    foreach ($n in 'AntivirusEnabled','AMServiceEnabled','RealTimeProtectionEnabled','IsTamperProtected','AMRunningMode') {
        Emit ('status\' + $n) $status.$n
    }
}
function Firmware {
    foreach ($n in 'SecureBoot','SetupMode','PK','KEK','db','dbx') {
        try {
            $v = Get-SecureBootUEFI -Name $n
            $sha = [Security.Cryptography.SHA256]::Create()
            try { Emit $n @{sha256=[BitConverter]::ToString($sha.ComputeHash($v.Bytes)).Replace('-',''); attributes=[string]$v.Attributes} }
            finally { $sha.Dispose() }
        } catch { Gap $n $_ }
    }
    $output = & "$env:SystemRoot\System32\bcdedit.exe" /enum firmware /v 2>&1
    if ($LASTEXITCODE) { Gap 'bootManager' ($output -join ' ') } else { Emit 'bootManager' ($output -join "\n") }
}
function GroupPolicy {
    foreach ($folder in 'GroupPolicy','GroupPolicyUsers') { PolicyFiles (Join-Path "$env:windir\System32" $folder) }
    $namespaces = @('root\rsop\computer')
    try {
        foreach ($child in Get-CimInstance -Namespace 'root\rsop\user' -ClassName '__Namespace') {
            $namespaces += 'root\rsop\user\' + $child.Name
        }
    } catch { Gap 'root\rsop\user' $_ }
    foreach ($ns in $namespaces) {
        try {
            foreach ($g in (Get-CimInstance -Namespace $ns -ClassName RSOP_GPO)) {
                Emit ($ns + '\' + $g.id) ([ordered]@{name=$g.name; id=$g.id; enabled=$g.enabled; version=$g.version; path=$g.fileSystemPath})
            }
        } catch { Gap $ns $_ }
    }
}
function SystemSettings {
    foreach ($arg in '/getactivescheme','/query') {
        try {
            $output = & "$env:SystemRoot\System32\powercfg.exe" $arg 2>&1
            if ($LASTEXITCODE) { Gap $arg ($output -join ' ') } else { Emit $arg ($output -join [Environment]::NewLine) }
        } catch { Gap $arg $_ }
    }
    $control = Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control'
    Emit 'serviceAutoStartDelay' ($control.GetValue('AutoStartDelay'))
}
function VolumeId($value) {
    $text = if ($value.DeviceID) { [string]$value.DeviceID } else { [string]$value }
    if ($text -match '(?i)Volume(\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\})') {
        return $matches[1].ToLowerInvariant()
    }
    throw 'Volume GUID unavailable'
}
function ShadowInventory {
    try {
        foreach ($storage in (Get-CimInstance -ClassName Win32_ShadowStorage)) {
            $src = VolumeId $storage.Volume
            $dst = VolumeId $storage.DiffVolume
            Emit ("storage\$src\$dst") @{volume=$src; storageVolume=$dst; maxBytes=[string]$storage.MaxSpace}
        }
    } catch { Gap 'storage' $_ }
    try {
        foreach ($copy in (Get-CimInstance -ClassName Win32_ShadowCopy)) {
            if (-not $copy.ID) { throw 'Shadow copy ID unavailable' }
            Emit ('copies\' + $copy.ID) @{volume=[string]$copy.VolumeName; setId=[string]$copy.SetID; persistent=$copy.Persistent}
        }
    } catch { Gap 'copies' $_ }
}
function Signatures {
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1')
    foreach ($path in (ConvertFrom-Json ([Console]::In.ReadToEnd()))) {
        try {
            $stream = [IO.File]::Open($path, 'Open', 'Read', 'Read')
            try {
                $s = Get-AuthenticodeSignature -LiteralPath $path
                $sha = [Security.Cryptography.SHA256]::Create()
                try { $hash = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','').ToLowerInvariant() }
                finally { $sha.Dispose() }
                Emit $path @{status=[string]$s.Status; osBinary=$s.IsOSBinary; type=[string]$s.SignatureType;
                    signer=$s.SignerCertificate.Subject; thumbprint=$s.SignerCertificate.Thumbprint; sha256=$hash}
            } finally { $stream.Dispose() }
        } catch { Gap $path $_ }
    }
}
function WmiStartup {
    foreach ($class in '__EventFilter','CommandLineEventConsumer','ActiveScriptEventConsumer','__FilterToConsumerBinding') {
        try {
            foreach ($obj in Get-CimInstance -Namespace root/subscription -ClassName $class) {
                $props = [ordered]@{}
                foreach ($p in $obj.CimInstanceProperties) { $props[$p.Name] = $p.Value }
                $id = if ($class -eq '__FilterToConsumerBinding') { [string]$obj.Filter + '|' + [string]$obj.Consumer } else { $obj.Name }
                Emit ($class + '\' + $id) $props
            }
        } catch { Gap $class $_ }
    }
}
function EventChanges {
    $table = @{
        'System'=@(7040,7045)
        'Security'=@(4657,4697,4698,4699,4700,4701,4702,4946,4947,4948)
        'Microsoft-Windows-TaskScheduler/Operational'=@(106,140,141,200)
        'Microsoft-Windows-Windows Defender/Operational'=@(1116,1117,1118,1119,1121,1122,1123,1124,1127,1128,1129,5001,5007,5010,5012,5013)
        'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'=@(2004,2005,2006)
        'Microsoft-Windows-Sysmon/Operational'=@(7,8,25)
    }
    $cursors = ConvertFrom-Json $env:WM_EVENT_CURSORS
    foreach ($channel in $table.Keys) {
        try {
            $log = Get-WinEvent -ListLog $channel
            if (-not $log.IsEnabled) { Gap $channel 'Event channel disabled'; continue }
            $high = 0L
            if ($log.RecordCount -gt 0) {
                $latest = Get-WinEvent -LogName $channel -MaxEvents 1
                try { $high = $latest.RecordId } finally { $latest.Dispose() }
            }
            $last = $cursors.PSObject.Properties[$channel]
            $events = New-Object 'System.Collections.Generic.List[object]'
            $note = ''
            $cursor = $high
            if ($last) {
                $floor = [long]$last.Value
                if ($high -lt $floor -or ($log.OldestRecordNumber -gt ($floor+1))) {
                    $note = 'Log cleared or rotated; prior records may be unavailable'
                    $floor = 0L
                }
                if ($high -gt $floor) {
                    $ids = (($table[$channel] | ForEach-Object { "EventID=$_" }) -join ' or ')
                    $xpath = "*[System[EventRecordID > $floor and EventRecordID <= $high and ($ids)]]"
                    $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($channel, 'LogName', $xpath)
                    $reader = New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)
                    try {
                        while ($event = $reader.ReadEvent()) {
                            try {
                                if ($events.Count -eq 200) {
                                    $cursor = $events[199].record
                                    $note += ' More matching events pending'
                                    break
                                }
                                $events.Add(@{record=$event.RecordId; id=$event.Id; provider=$event.ProviderName;
                                    time=$event.TimeCreated.ToUniversalTime().ToString('o'); xml=$event.ToXml()})
                            } finally { $event.Dispose() }
                        }
                    } finally { $reader.Dispose() }
                }
            } else { $note = 'Started observing at current end of log' }
            Emit $channel @{cursor=$cursor; events=$events.ToArray(); note=$note}
        } catch { Gap $channel $_ }
    }
}
try {
    switch ($Section) {
        tasks { $ts = New-Object -ComObject Schedule.Service; $ts.Connect(); TaskFolder ($ts.GetFolder('\')) }
        firewall { Firewall }
        defender { Defender }
        firmware { Firmware }
        gpo { GroupPolicy }
        wmi { WmiStartup }
        events { EventChanges }
        system { SystemSettings }
        shadows { ShadowInventory }
        signatures { Signatures }
        default { throw 'Unknown section' }
    }
} catch { Gap '' $_ }
