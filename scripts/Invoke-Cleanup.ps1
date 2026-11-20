[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ListPath,[switch]$Execute,[switch]$UserAuthorized,[string]$ResultPath)
. "$PSScriptRoot\Common.ps1"
if($Execute -and -not $UserAuthorized){throw 'Execution requires user authorization: active delivery of a cleanup list under this Skill agreement or an explicit execution request. Do not set -UserAuthorized for read-only requests or passively discovered files.'}
$raw=[IO.File]::ReadAllText([IO.Path]::GetFullPath($ListPath),[Text.Encoding]::UTF8)
$match=[regex]::Matches($raw,'(?m)^DISK_CLEANUP_MANIFEST_BEGIN\r?\n([^\r\n]+)\r?\nDISK_CLEANUP_MANIFEST_END\s*$')
if($match.Count -ne 1){throw 'Missing/ambiguous versioned manifest. A legacy list needs a fresh scan/export; do not guess its scope.'}
$data=ConvertFrom-Json -InputObject $match[0].Groups[1].Value
Assert-Data $data
if($data.execution.mode -ne 'permanent' -or -not $data.execution.requiresUserInstruction){throw 'Unsupported execution mode.'}
if([DiskCleanup.Core]::Volume($data.scan.drive) -ne $data.scan.volumeId){throw 'The drive now identifies a different volume.'}
$disk=New-Object IO.DriveInfo($data.scan.drive);$before=$disk.AvailableFreeSpace
$results=New-Object Collections.Generic.List[object]
function Test-Target($t){
    if(-not (Test-Path -LiteralPath $t.path)){return 'missing'}
    if(-not [DiskCleanup.Core]::NoLinks($t.path)){throw 'A link was introduced into the path.'}
    if([DiskCleanup.Core]::FileId($t.path) -ne $t.fileId){throw 'File identity changed.'}
    if($t.type -eq 'file'){
        $f=Get-Item -LiteralPath $t.path
        if($f.PSIsContainer -or $f.Length -ne $t.size -or $f.LastWriteTimeUtc.Ticks -ne $t.modifiedTicks){throw 'File changed since scan.'}
        $kind=[DiskCleanup.Core]::ClassifyFile($t.path,$f.Length,$f.LastWriteTimeUtc.Ticks,[DiskCleanup.Core]::Metadata($t.path))
        if($kind -ne $t.kind -or $t.ruleId -ne ($kind+'-file-v1')){throw 'Current file no longer satisfies the cleanup rule.'}
    }else{
        if(-not (Test-Path -LiteralPath $t.path -PathType Container)){throw 'Target type changed.'}
        $kind=[DiskCleanup.Core]::Scope($t.path)
        if($kind -ne $t.kind -or $t.ruleId -ne ($kind+'-leaf-v1')){throw 'Invalid leaf cleanup scope.'}
        $members=[DiskCleanup.Core]::Members($t.path)
        if([DiskCleanup.Core]::Fingerprint($members) -ne $t.fingerprint){throw 'Directory contents changed since scan.'}
        if($kind -in @('browsercache','appcache')){if(-not [DiskCleanup.Core]::CacheFormat($t.path,$kind)){throw 'Cache format no longer verified.'}}
        else {foreach($m in $members){$p=Join-Path $t.path $m.name;if([DiskCleanup.Core]::ClassifyFile($p,$m.size,$m.modifiedTicks,'') -ne $kind){throw 'Mixed or recent directory contents.'}}}
    }
    'ready'
}
foreach($t in @($data.targets)){
    try{
        $state=Test-Target $t
        if($state -eq 'ready' -and $Execute){
            if($t.type -eq 'file'){[DiskCleanup.Core]::DeleteExactFile($t.path,$t.size,$t.modifiedTicks,$t.fileId)}
            else{[DiskCleanup.Core]::DeleteExactLeaf($t.path,$t.fileId,$t.fingerprint)}
            if(Test-Path -LiteralPath $t.path){throw 'Target still exists after deletion.'};$state='deleted'
        }
        $results.Add([ordered]@{path=$t.path;name=(@($data.cards|Where-Object{$_.targetIds -contains $t.id})[0].name);status=$state;bytes=$t.size;reason=''})
    }catch{$results.Add([ordered]@{path=$t.path;status='skipped';bytes=0;reason=$_.Exception.Message})}
}
# Split registry commands with the Windows parser; never evaluate shell text.
Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;
public static class CleanupCommandLine {
 [DllImport("shell32.dll",SetLastError=true)]static extern IntPtr CommandLineToArgvW([MarshalAs(UnmanagedType.LPWStr)]string command,out int count);
 [DllImport("kernel32.dll")]static extern IntPtr LocalFree(IntPtr value);
 public static string[] Split(string command){int n;IntPtr p=CommandLineToArgvW(command,out n);if(p==IntPtr.Zero)throw new Exception("Invalid official uninstall command");try{var a=new string[n];for(int i=0;i<n;i++)a[i]=Marshal.PtrToStringUni(Marshal.ReadIntPtr(p,i*IntPtr.Size));return a;}finally{LocalFree(p);}}
}
'@
$registered=@(Get-RegisteredApps)
$script:settingsOpened=$false
function Add-UninstallManual($app,[string]$reason){
    if($Execute -and -not $script:settingsOpened){Start-Process -FilePath 'ms-settings:appsfeatures';$script:settingsOpened=$true}
    $results.Add([ordered]@{name=$app.name;status='uninstall-manual';reason=$reason+' Use Windows Settings > Apps > Installed apps and the official Uninstall action; do not delete data directories.'})
}
foreach($cat in @('apps','devTools')){foreach($app in @($data.softwareInsights.$cat.list)){
    $officialMatched=$false
    try{
        if(-not $app.canUninstall){throw 'Not an uninstallable application.'}
        if($app.PSObject.Properties['uninstallMode'] -and $app.uninstallMode -eq 'settings'){
            Add-UninstallManual $app 'Select the matching application/version.';continue
        }
        $registeredName=if($app.PSObject.Properties['registeredDisplayName'] -and $app.registeredDisplayName){$app.registeredDisplayName}else{$app.name}
        $current=@($registered|Where-Object{$_.key -eq $app.uninstallKey -and $_.name -eq $registeredName -and $_.category -eq 'registered' -and -not $_.protectedApp})
        if($current.Count -eq 0){$results.Add([ordered]@{name=$app.name;status='uninstall-missing';reason='Official uninstall registration absent or changed.'});continue}
        $officialMatched=$true
        $key='Registry::'+$app.uninstallKey;$v=Get-ItemProperty -LiteralPath $key
        if(-not $v.PSObject.Properties['UninstallString']){throw 'No official uninstall command.'}
        $command=[Environment]::ExpandEnvironmentVariables([string]$v.UninstallString);$argv=[CleanupCommandLine]::Split($command)
        $exe=$argv[0];$arguments=@($argv|Select-Object -Skip 1)
        if($exe -match '^(?i)msiexec(?:\.exe)?$'){$exe=Join-Path ([Environment]::GetFolderPath('System')) 'msiexec.exe'}
        if(-not [IO.Path]::IsPathRooted($exe) -or -not (Test-Path -LiteralPath $exe -PathType Leaf)){throw 'Official command does not identify an existing executable.'}
        if([IO.Path]::GetFileName($exe) -match '^(cmd|powershell|pwsh|wscript|cscript|rundll32|regsvr32|mshta)\.exe$'){throw 'Shell/script uninstall entry requires individual inspection.'}
        if(-not [DiskCleanup.Core]::NoLinks($exe)){throw 'Linked uninstall executable.'}
        $signature=Get-AuthenticodeSignature -LiteralPath $exe
        if($signature.Status -ne 'Valid'){throw 'Official uninstall executable lacks a valid signature; individual verification required.'}
        if([IO.Path]::GetFileName($exe) -ieq 'msiexec.exe'){
            $guids=@($arguments|Where-Object{$_ -match '^/?[ix]?\{[0-9a-fA-F-]{36}\}$'})
            $joined=$arguments -join ' ';$guidMatch=[regex]::Match($joined,'\{[0-9a-fA-F-]{36}\}')
            if(-not $guidMatch.Success){throw 'MSI uninstall entry has no product identity.'}
            $arguments=@('/x',$guidMatch.Value,'/norestart')
        }
        if(-not $Execute){$results.Add([ordered]@{name=$app.name;status='uninstall-ready';reason='Verified signed official uninstall entry.'});continue}
        # Round-trip quote each argument for native CreateProcess; no command interpreter.
        $quoted=@(foreach($a in $arguments){'"'+[regex]::Replace([regex]::Replace($a,'(\\*)"','$1$1\"'),'(\\+)$','$1$1')+'"'})
        $start=@{FilePath=$exe;PassThru=$true}
        if($quoted.Count){$start.ArgumentList=$quoted -join ' '}
        $process=Start-Process @start
        if(-not $process.WaitForExit(60000)){$results.Add([ordered]@{name=$app.name;status='uninstall-running';processId=$process.Id;reason='Official interface is open; follow it without killing or relaunching the process.'});continue}
        $still=@(Get-RegisteredApps|Where-Object{$_.key -eq $app.uninstallKey}).Count -gt 0
        $results.Add([ordered]@{name=$app.name;status=$(if($still){'uninstall-needs-review'}else{'uninstalled'});exitCode=$process.ExitCode;reason=$(if($still){'Registration remains; do not claim success.'}else{'Official registration removed.'})})
    }catch{
        if($officialMatched){Add-UninstallManual $app $_.Exception.Message}
        else{$results.Add([ordered]@{name=$app.name;status='uninstall-skipped';reason=$_.Exception.Message})}
    }
}}
$after=(New-Object IO.DriveInfo($data.scan.drive)).AvailableFreeSpace
$report=[ordered]@{scanId=$data.scan.id;executed=[bool]$Execute;time=[DateTimeOffset]::Now.ToString('o');drive=$data.scan.drive;freeBefore=$before;freeAfter=$after;actualFreeChange=$after-$before;results=@($results.ToArray())}
if(-not $ResultPath){$ResultPath=Join-Path (Split-Path ([IO.Path]::GetFullPath($ListPath)) -Parent) ('cleanup-result-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'.json')}
Write-JsonFile $report $ResultPath
$report.results | ForEach-Object {[pscustomobject]$_} | Format-Table status,path,name,reason -AutoSize
Write-Output ('Result: '+[IO.Path]::GetFullPath($ResultPath))
