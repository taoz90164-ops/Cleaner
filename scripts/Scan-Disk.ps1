[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Root,[string]$OutputDirectory)
. "$PSScriptRoot\Common.ps1"
$resolved=[IO.Path]::GetFullPath($Root)
if($resolved -notmatch '^[A-Za-z]:\\' -or -not (Test-Path -LiteralPath $resolved -PathType Container)){throw 'Specify an existing local Windows drive or directory.'}
if(-not [DiskCleanup.Core]::NoLinks($resolved)){throw 'Scan root cannot contain links.'}
$drive=[IO.Path]::GetPathRoot($resolved);$volume=New-Object IO.DriveInfo($drive)
if($volume.DriveType -notin @([IO.DriveType]::Fixed,[IO.DriveType]::Removable)){throw 'Only local fixed/removable drives are supported.'}
$scanId=[Guid]::NewGuid().ToString('N');$date=[DateTimeOffset]::Now.ToString('o')
if(-not $OutputDirectory){$OutputDirectory=Join-Path $Script:SkillRoot ('reports\'+$drive.Substring(0,1)+'-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))}
$apps=@(Get-RegisteredApps);$personal=@{}
foreach($pair in @(@('Desktop','桌面文件'),@('MyDocuments','文档与项目'),@('MyPictures','图片与素材'),@('MyVideos','视频与素材'),@('MyMusic','音乐文件'))) {
    $p=[Environment]::GetFolderPath([Environment+SpecialFolder]$pair[0]);if($p){$personal[$p]=$pair[1]}
}
$userShell='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
if(Test-Path -LiteralPath $userShell){$v=Get-ItemProperty -LiteralPath $userShell;$prop=$v.PSObject.Properties['{374DE290-123F-4565-9164-39C4925E467B}'];if($prop){$personal[[Environment]::ExpandEnvironmentVariables([string]$prop.Value)]='下载的文件'}}
# Other local profiles are located from the live profile registry, not a fixed username.
foreach($profile in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction SilentlyContinue){
    $v=Get-ItemProperty -LiteralPath $profile.PSPath -ErrorAction SilentlyContinue
    if($v -and $v.PSObject.Properties['ProfileImagePath']){$homePath=[Environment]::ExpandEnvironmentVariables([string]$v.ProfileImagePath);foreach($entry in @(@('Desktop','桌面文件'),@('Documents','文档与项目'),@('Downloads','下载的文件'),@('Pictures','图片与素材'),@('Videos','视频与素材'),@('Music','音乐文件'))){$p=Join-Path $homePath $entry[0];if(-not $personal.ContainsKey($p)){$personal[$p]=$entry[1]}}}
}
Write-Host ('Scanning '+$resolved+' ...')
$timer=[Diagnostics.Stopwatch]::StartNew();$keys=@($personal.Keys)
$result=[DiskCleanup.Core]::Scan($resolved,[DiskCleanup.RegisteredApp[]]$apps,[string[]]$keys,[string[]]@($keys|ForEach-Object{$personal[$_]}))
# Filter only after folder aggregation; small files remain in leaf snapshots.
$targets=@($result.targets | Where-Object {$_.size -ge 10000000})
$cards=@(foreach($t in $targets){
    $name=switch($t.kind){'temp'{'软件临时碎片'};'logs'{if($t.app){$t.app+'故障记录'}else{'软件故障记录'}};'package'{$t.app+'安装与更新包'};'browsercache'{$t.app+'网页缓存'};'appcache'{$t.app+'页面缓存'};'cache'{if($t.path -match '\.gradle'){'开发工具编译缓存'}else{'前端代码依赖包缓存'}}}
    [ordered]@{id='card-'+$t.id;name=$name;kind=$t.kind;size=$t.size;targetIds=@($t.id)}
})
$insights=[ordered]@{}
foreach($cat in @('apps','personal','devTools')){
    $list=@(foreach($e in @($result.entities | Where-Object {$_.category -eq $cat -and $_.size -ge 10000000} | Sort-Object size -Descending)){
        $details=@(foreach($p in $e.paths.Keys){[ordered]@{path=$p;sizeBytes=$e.paths[$p]}})
        $can=$e.canUninstall -and @($apps|Where-Object{$_.key -eq $e.uninstallKey -and $_.category -eq 'registered'}).Count -gt 0
        [ordered]@{id=[DiskCleanup.Core]::Id(($e.paths.Keys|Select-Object -First 1));name=$e.name;category=$cat;subtype=$e.subtype;sizeBytes=$e.size;sizeGB=$e.size/1e9;paths=@($e.paths.Keys);pathDetails=$details;tag=$e.tag;iconType=$e.iconType;guide=$e.guide;contentDescription=$e.contentDescription;canUninstall=[bool]$can;uninstallKey=$e.uninstallKey;uninstallProtection=$(if($e.subtype -eq 'component'){'system'}else{'data'})}
    })
    $insights[$cat]=[ordered]@{list=$list}
}
$data=[ordered]@{schemaVersion=3;templateVersion='1.0.0';date=$date;softwareInsightsScannedAt=$date;scan=[ordered]@{id=$scanId;root=$resolved;skillRoot=$Script:SkillRoot;drive=$drive;volumeId=[DiskCleanup.Core]::Volume($drive);volumeLabel=$volume.VolumeLabel;files=$result.files;logicalBytes=$result.bytes;elapsedSeconds=$timer.Elapsed.TotalSeconds};disk=[ordered]@{total=$volume.TotalSize;used=$volume.TotalSize-$volume.AvailableFreeSpace;free=$volume.AvailableFreeSpace;systemLockedBytes=$result.systemBytes};cards=$cards;targets=$targets;softwareInsights=$insights;errors=@($result.errors);skipped=@($result.skipped)}
# Convert to the same property model used by imported JSON before validation.
$normalized=ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $data -Depth 100 -Compress)
Resolve-InsightEvidence $normalized
Assert-Data $normalized
$jsonPath=Join-Path $OutputDirectory 'scan.json';Write-JsonFile $normalized $jsonPath
& "$PSScriptRoot\Build-Report.ps1" -DataPath $jsonPath -OutputPath (Join-Path $OutputDirectory ($drive.Substring(0,1)+'盘空间分析.html'))
Write-Output ([pscustomobject]@{scan=$jsonPath;files=$result.files;cards=$cards.Count;entities=$result.entities.Count;errors=$result.errors.Count;skipped=$result.skipped.Count;seconds=[Math]::Round($timer.Elapsed.TotalSeconds,1)})
