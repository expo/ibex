# Print the OS ICU / CLDR / Unicode / tzdata versions and en_US time patterns.
$here = $PSScriptRoot
$repo = Resolve-Path (Join-Path $here '..\..')
. (Join-Path $here 'vcenv.ps1')
$out = Join-Path $repo 'target\win-intl-versions'
New-Item -ItemType Directory -Force $out | Out-Null
Set-Location $out
& cl /nologo /std:c++17 /EHsc /utf-8 (Join-Path $here 'versions.cc') /Fe:versions.exe /link icu.lib | Out-Null
& .\versions.exe
