Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$Script:SkillRoot = Split-Path $PSScriptRoot -Parent
if (-not ('DiskCleanup.Core' -as [type])) { Add-Type -Path (Join-Path $PSScriptRoot 'DiskCore.cs') }
function Write-JsonFile($Value, [string]$Path) {
    $parent = Split-Path ([IO.Path]::GetFullPath($Path)) -Parent
    [IO.Directory]::CreateDirectory($parent) | Out-Null
    [IO.File]::WriteAllText([IO.Path]::GetFullPath($Path), (ConvertTo-Json -InputObject $Value -Depth 100 -Compress), (New-Object Text.UTF8Encoding($false)))
}
function Read-JsonFile([string]$Path) { ConvertFrom-Json -InputObject ([IO.File]::ReadAllText([IO.Path]::GetFullPath($Path), [Text.Encoding]::UTF8)) }
function Get-RegisteredApps {
    foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($key in Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue) {
            $v = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction SilentlyContinue
            if (-not $v -or -not $v.PSObject.Properties['DisplayName']) { continue }
            $location = if ($v.PSObject.Properties['InstallLocation']) { [string]$v.InstallLocation } else { '' }
            $uninstall = if ($v.PSObject.Properties['UninstallString']) { [string]$v.UninstallString } else { '' }
            $protected = ($v.PSObject.Properties['SystemComponent'] -and $v.SystemComponent -eq 1) -or ([DiskCleanup.Core]::OtherSubtype($v.DisplayName) -eq 'component')
            $app = New-Object DiskCleanup.RegisteredApp
            $app.name = [string]$v.DisplayName; $app.key = $key.Name; $app.protectedApp = [bool]$protected
            try { $location=$location.Trim('"'); if ($location -and [IO.Path]::IsPathRooted($location) -and (Test-Path -LiteralPath $location -PathType Container)) { $app.location = [IO.Path]::GetFullPath($location) } } catch { $app.location='' }
            $app.category = if ($uninstall) { 'registered' } else { 'no-uninstall' }
            $roots=@()
            if([DiskCleanup.Core]::IsSpecificAppLocation($app.location)){$roots+=@($app.location)}
            # Read command/icon paths as data; never launch them during scanning.
            foreach($field in @('UninstallString','DisplayIcon')){
                if(-not $v.PSObject.Properties[$field]){continue}
                $value=[Environment]::ExpandEnvironmentVariables([string]$v.$field)
                $match=[regex]::Match($value,'^(?:"(?<exe>[A-Za-z]:\\[^"\r\n]+\.exe)"|(?<exe>[A-Za-z]:\\[^\r\n]+?\.exe))(?=\s|,|$)','IgnoreCase')
                if(-not $match.Success){continue}
                $exe=$match.Groups['exe'].Value
                if([IO.Path]::GetFileName($exe) -match '^(?i)(msiexec|rundll32|cmd|powershell|pwsh|wscript|cscript|mshta)\.exe$'){continue}
                $parent=[IO.Path]::GetDirectoryName($exe)
                if((Test-Path -LiteralPath $exe -PathType Leaf) -and [DiskCleanup.Core]::IsSpecificAppLocation($parent)){$roots+=@($parent)}
            }
            $app | Add-Member -NotePropertyName uninstallRoots -NotePropertyValue @($roots|Select-Object -Unique)
            $app
        }
    }
}
function Resolve-UninstallEvidence($Data, $RegisteredApps = @(Get-RegisteredApps)) {
    # Exact known-product aliases only. Versions may follow a space; no fuzzy substring match.
    $aliases=@{
        '剪映专业版'='^(剪映专业版|CapCut)(?:\s+\d[\w. -]*)?$'
        'Steam 游戏库与启动器'='^Steam$'
        '微信'='^(微信|WeChat|Weixin)(?:\s+\d[\w. -]*)?$'
        '飞书'='^(飞书|Feishu|Lark)(?:\s+\d[\w. -]*)?$'
        '豆包'='^(豆包|Doubao)(?:\s+\d[\w. -]*)?$'
        '育碧游戏启动器'='^(Ubisoft Connect|Ubisoft Game Launcher|Uplay)(?:\s+\d[\w. -]*)?$'
        '谷歌浏览器'='^Google Chrome$'
        '微软 Edge 浏览器'='^Microsoft Edge$'
        'WPS Office'='^(WPS Office|WPS)(?:\s+\d[\w. -]*)?$'
    }
    foreach($category in @('apps','personal','devTools')){foreach($e in @($Data.softwareInsights.$category.list)){
        $locked=$category -eq 'personal' -or $e.subtype -in @('component','unknown') -or $e.uninstallProtection -eq 'system'
        if($locked){$e.canUninstall=$false;continue}
        $candidates=@($RegisteredApps|Where-Object{$_.category -eq 'registered' -and -not $_.protectedApp -and $e.uninstallKey -and $_.key -eq $e.uninstallKey})
        if(-not $candidates.Count){
            $candidates=@($RegisteredApps|Where-Object{
                $_.category -eq 'registered' -and -not $_.protectedApp -and
                ($_.name -ieq $e.name -or ($aliases.ContainsKey($e.name) -and $_.name -match $aliases[$e.name]))
            })
        }
        $mode='';$key='';$display='';$details=@();$reason=''
        if($candidates.Count -eq 1){
            $a=$candidates[0];$mode='registry';$key=$a.key;$display=$a.name
            $roots=if($a.PSObject.Properties['uninstallRoots']){@($a.uninstallRoots)}else{@($a.location)}
            foreach($d in @($e.pathDetails)){
                $inside=@($roots|Where-Object{[DiskCleanup.Core]::IsSpecificAppLocation($_) -and [DiskCleanup.Core]::Within($d.path,$_)}).Count -gt 0
                if($inside){$details+=@([pscustomobject]@{path=$d.path;sizeBytes=[long]$d.sizeBytes})}
            }
            $reason='已匹配官方卸载登记'
        }elseif($category -eq 'apps'){
            # Verified third-party ownership does not imply a unique registry registration.
            # Keep a visible pending-uninstall route; execution resolves through Windows Settings.
            $mode='settings';$reason=if($candidates.Count -gt 1){'存在多个官方安装记录，需在系统已安装应用中选择对应版本'}else{'未找到唯一官方卸载记录，需在系统已安装应用中确认'}
        }
        $e.canUninstall=[bool]$mode;$e.uninstallKey=$key
        $e|Add-Member -NotePropertyName uninstallMode -NotePropertyValue $mode -Force
        $e|Add-Member -NotePropertyName registeredDisplayName -NotePropertyValue $display -Force
        $e|Add-Member -NotePropertyName uninstallResolution -NotePropertyValue $reason -Force
        $e|Add-Member -NotePropertyName uninstallPathDetails -NotePropertyValue @($details) -Force
        $estimate=0L;foreach($d in $details){$estimate+=[long]$d.sizeBytes}
        $e|Add-Member -NotePropertyName uninstallEstimateBytes -NotePropertyValue $estimate -Force
    }}
}
function Resolve-InsightEvidence($Data) {
    # Full-disk reports must not recommend synthetic fixtures created by this skill.
    # A scan explicitly rooted at a fixture still exercises the normal test rules.
    $excluded=@{};$keptTargets=@()
    foreach($target in @($Data.targets)){
        $parent=[IO.Path]::GetDirectoryName($target.path);$fixture=''
        while($parent){
            if((Test-Path -LiteralPath (Join-Path $parent '.disk-cleanup-test-fixture') -PathType Leaf) -and -not [DiskCleanup.Core]::Within($Data.scan.root,$parent)){$fixture=$parent;break}
            $parent=[IO.Path]::GetDirectoryName($parent)
        }
        if($fixture){$excluded[$fixture]=$true}else{$keptTargets+=@($target)}
    }
    $Data.targets=@($keptTargets);$keptById=@{};foreach($t in $keptTargets){$keptById[$t.id]=$t}
    $Data.cards=@(foreach($card in @($Data.cards)){
        $card.targetIds=@($card.targetIds|Where-Object{$keptById.ContainsKey($_)})
        $card.size=0L;foreach($id in $card.targetIds){$card.size+=$keptById[$id].size}
        if($card.size -ge 10000000){$card}
    })
    $Data.scan | Add-Member -NotePropertyName excludedCleanupTestRoots -NotePropertyValue @($excluded.Keys) -Force
    # Enrich existing measured entities only; never expand paths or invent sizes.
    foreach($e in @($Data.softwareInsights.devTools.list)) {
        if($e.subtype -ne 'unknown' -or @($e.paths).Count -ne 1){continue}
        $path=[string]$e.paths[0]
        if(-not (Test-Path -LiteralPath $path -PathType Container) -or -not [DiskCleanup.Core]::NoLinks($path)){continue}
        $name=[IO.Path]::GetFileName($path.TrimEnd('\'));$category='';$title='';$evidence=''
        if($name -ieq 'steam'){
            $exe=Join-Path $path 'steam.exe'
            if((Test-Path -LiteralPath $exe -PathType Leaf) -and (Test-Path -LiteralPath (Join-Path $path 'steamapps') -PathType Container) -and [Diagnostics.FileVersionInfo]::GetVersionInfo($exe).ProductName -eq 'Steam'){
                $category='apps';$title='Steam 游戏库与启动器';$evidence='steam.exe 产品信息为 Steam，且存在 steamapps 游戏库'
            }
        }elseif($name -in @('BaiduNetdiskDownload','LeStoreDownload','QLDownload','rrdownload','安装包')){
            $category='personal';$title=switch($name){'BaiduNetdiskDownload'{'百度网盘下载的文件'};'LeStoreDownload'{'软件商店下载的文件'};'QLDownload'{'下载保存的文件'};'rrdownload'{'下载保存的视频'};'安装包'{'自己保存的安装包'}}
            $evidence='已维护的独立下载容器名称；作为个人资产保留，不作为软件本体或整目录删除目标'
        }
        if(-not $category){continue}
        $e.name=$title;$e.category=$category;$e.subtype=if($category -eq 'personal'){'asset'}else{''}
        $e.tag=if($category -eq 'personal'){'下载保存的文件'}else{'游戏库与软件程序'}
        $e.iconType=if($category -eq 'personal'){'document'}else{'game'}
        $e.guide=if($category -eq 'personal'){'打开下载文件夹 → 挑出需要保留的文件 → 按需整理或搬到其他盘。'}else{'打开 Steam → 设置 → 存储空间 → 选择游戏迁移或卸载。'}
        $e.contentDescription=if($category -eq 'personal'){'下载后保存在电脑里的文件，不等同于可直接清空的缓存。'}else{'Steam 启动器和已下载的游戏资源。'}
        $e.canUninstall=$false;$e.uninstallKey='';$e.uninstallProtection='data'
        $e | Add-Member -NotePropertyName classificationEvidence -NotePropertyValue $evidence -Force
        $Data.softwareInsights.devTools.list=@($Data.softwareInsights.devTools.list|Where-Object{$_.id -ne $e.id})
        $Data.softwareInsights.$category.list=@($Data.softwareInsights.$category.list)+@($e)
    }
    Resolve-UninstallEvidence $Data
    foreach($category in @('apps','personal','devTools')){$Data.softwareInsights.$category.list=@($Data.softwareInsights.$category.list|Sort-Object sizeBytes -Descending)}
}
function Assert-Data($Data) {
    if ($Data.schemaVersion -ne 3 -or $Data.templateVersion -ne '1.0.0') { throw 'Unsupported data/template version.' }
    if ($Data.disk.total -le 0 -or $Data.disk.used -lt 0 -or $Data.disk.free -lt 0 -or [Math]::Abs($Data.disk.total-$Data.disk.used-$Data.disk.free) -gt 4096) { throw 'Invalid disk accounting.' }
    if ($Data.scan.root -notmatch '^[A-Za-z]:\\' -or $Data.scan.drive -ne [IO.Path]::GetPathRoot($Data.scan.root)) { throw 'Invalid scan root/drive.' }
    $targetMap = @{}; $paths = @{}
    foreach ($t in @($Data.targets)) {
        if ($t.type -notin @('file','folder') -or $t.kind -notin @('temp','logs','package','browsercache','appcache','cache')) { throw 'Invalid target kind/type.' }
        if (-not [DiskCleanup.Core]::Within($t.path,$Data.scan.root) -or [DiskCleanup.Core]::Norm($t.path) -eq [DiskCleanup.Core]::Norm($Data.scan.root) -or [DiskCleanup.Core]::Protected($t.path) -or $t.path -match '[\r\n*?]' -or $t.path.Substring(2).Contains(':')) { throw "Invalid/protected target: $($t.path)" }
        if (-not $t.complete -or $t.size -le 0 -or -not $t.fileId -or -not $t.ruleId) { throw 'Missing target evidence.' }
        $pathKey=[DiskCleanup.Core]::Norm($t.path)
        if ($targetMap.ContainsKey($t.id) -or $paths.ContainsKey($pathKey)) { throw 'Duplicate target.' };$targetMap[$t.id]=$t;$paths[$pathKey]=$t
        if ($t.type -eq 'folder') {
            if (-not $t.fingerprint -or @($t.members).Count -eq 0) { throw 'Missing leaf membership snapshot.' }
            $sum=0L;$names=@{}
            foreach($m in @($t.members)) { if (-not $m.name -or [IO.Path]::GetFileName($m.name) -ne $m.name -or $m.name -match '[\r\n:*?\\/]' -or $names.ContainsKey($m.name) -or -not $m.fileId) { throw 'Invalid directory member.' };$names[$m.name]=$true;$sum += [long]$m.size }
            if($sum -ne $t.size) { throw 'Directory size mismatch.' }
        }
    }
    foreach($t in @($Data.targets)) { $p=[IO.Path]::GetDirectoryName($t.path);while($p){$key=[DiskCleanup.Core]::Norm($p);if($paths.ContainsKey($key)-and $paths[$key].type -eq 'folder'){throw 'Overlapping targets.'};$p=[IO.Path]::GetDirectoryName($p)} }
    $cards=@{};$referenced=@{}
    foreach ($c in @($Data.cards)) {
        if ($cards.ContainsKey($c.id) -or -not $c.name -or $c.kind -notin @('temp','logs','package','browsercache','appcache','cache') -or @($c.targetIds).Count -eq 0) { throw 'Invalid card.' };$cards[$c.id]=$true
        $sum=0L;$seen=@{}
        foreach($id in @($c.targetIds)){if(-not $targetMap.ContainsKey($id)-or $seen.ContainsKey($id)-or $referenced.ContainsKey($id)-or $targetMap[$id].kind -ne $c.kind){throw 'Missing, shared or mismatched card target.'};$seen[$id]=$true;$referenced[$id]=$true;$sum += [long]$targetMap[$id].size}
        if($sum -ne $c.size -or $c.size -lt 10000000){throw 'Invalid card size.'}
    }
    if($referenced.Count -ne $targetMap.Count){throw 'Orphan cleanup target.'}
    foreach($category in @('apps','personal','devTools')) {
        foreach($e in @($Data.softwareInsights.$category.list)) {
            if($e.sizeBytes -lt 10000000 -or -not $e.name -or $e.category -ne $category -or @($e.paths).Count -eq 0){throw 'Invalid insight entity.'}
            foreach($path in $e.paths){if(-not [DiskCleanup.Core]::Within($path,$Data.scan.root)){throw 'Cross-volume insight path.'}}
            if($category -eq 'personal' -and $e.canUninstall){throw 'Personal assets cannot be uninstalled.'}
            if($category -eq 'devTools' -and $e.subtype -notin @('development','virtual','professional','component','unknown')){throw 'Other category requires a recognized subtype.'}
            if($category -eq 'apps' -and $e.subtype -in @('development','virtual','professional','component','unknown','asset')){throw 'Misclassified common application.'}
            if($e.subtype -in @('component','unknown') -and $e.canUninstall){throw 'Unknown/system entities cannot be uninstalled.'}
            $mode=if($e.PSObject.Properties['uninstallMode']){[string]$e.uninstallMode}else{'registry'}
            if($e.canUninstall -and $mode -notin @('registry','settings')){throw 'Invalid official uninstall route.'}
            if($e.canUninstall -and $mode -eq 'registry' -and -not $e.uninstallKey){throw 'Missing official uninstall registration.'}
            if($e.canUninstall -and $mode -eq 'settings' -and ($category -ne 'apps' -or $e.uninstallKey)){throw 'Ambiguous uninstall must use Windows Settings without an arbitrary registry key.'}
            if($e.PSObject.Properties['uninstallEstimateBytes']){
                $sum=0L;$seen=@{}
                foreach($detail in @($e.uninstallPathDetails)){
                    $matches=@($e.pathDetails|Where-Object{$_.path -eq $detail.path -and $_.sizeBytes -eq $detail.sizeBytes})
                    if($matches.Count -ne 1 -or $seen.ContainsKey($detail.path)){throw 'Invalid measured uninstall estimate.'}
                    $seen[$detail.path]=$true;$sum+=[long]$detail.sizeBytes
                }
                if($sum -ne $e.uninstallEstimateBytes -or $sum -lt 0 -or $sum -gt $e.sizeBytes){throw 'Invalid uninstall estimate total.'}
            }
        }
    }
}
