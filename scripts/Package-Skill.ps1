[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$OutputPath)
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$expected=[IO.File]::ReadAllText((Join-Path $root 'assets\template.sha256')).Trim()
if((Get-FileHash -LiteralPath (Join-Path $root 'assets\report-template.html') -Algorithm SHA256).Hash -ne $expected){throw 'Template integrity check failed; package not created.'}
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$output=[IO.Path]::GetFullPath($OutputPath)
if(Test-Path -LiteralPath $output){throw 'Package already exists; choose a new output name.'}
[IO.Directory]::CreateDirectory((Split-Path $output -Parent))|Out-Null
$zip=[IO.Compression.ZipFile]::Open($output,[IO.Compression.ZipArchiveMode]::Create)
try{
    $files=@(Get-Item -LiteralPath (Join-Path $root 'SKILL.md'))
    $files+=@(Get-Item -LiteralPath (Join-Path $root '新手使用规则.txt'))
    foreach($dir in @('assets','scripts','references')){$files+=@(Get-ChildItem -LiteralPath (Join-Path $root $dir) -File -Recurse)}
    foreach($file in $files){$relative=$file.FullName.Substring($root.Length+1).Replace('\','/');[IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip,$file.FullName,('Cleaner/'+$relative),[IO.Compression.CompressionLevel]::Optimal)|Out-Null}
}finally{$zip.Dispose()}
Write-Output $output
