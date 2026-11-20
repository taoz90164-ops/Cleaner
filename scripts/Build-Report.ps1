[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$DataPath,[Parameter(Mandatory=$true)][string]$OutputPath)
. "$PSScriptRoot\Common.ps1"
$data=Read-JsonFile $DataPath;Assert-Data $data
$templatePath=Join-Path $Script:SkillRoot 'assets\report-template.html'
$expected=([IO.File]::ReadAllText((Join-Path $Script:SkillRoot 'assets\template.sha256'))).Trim()
if((Get-FileHash -LiteralPath $templatePath -Algorithm SHA256).Hash -ne $expected){throw 'Template integrity check failed. Do not rewrite the template to accommodate scan data.'}
$template=[IO.File]::ReadAllText($templatePath,[Text.Encoding]::UTF8)
if([regex]::Matches($template,'__SCAN_DATA__').Count -ne 1){throw 'Invalid template data slot.'}
$json=ConvertTo-Json -InputObject $data -Depth 100 -Compress
$json=$json.Replace('<','\u003c').Replace('>','\u003e').Replace('&','\u0026').Replace([string][char]0x2028,'\u2028').Replace([string][char]0x2029,'\u2029')
$result=$template.Replace('__SCAN_DATA__',$json)
$full=[IO.Path]::GetFullPath($OutputPath);[IO.Directory]::CreateDirectory((Split-Path $full -Parent))|Out-Null
[IO.File]::WriteAllText($full,$result,(New-Object Text.UTF8Encoding($false)))
Write-Output $full
