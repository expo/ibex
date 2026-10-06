# Build and run the direct shim harness against the SDK icu.lib (no Rust/JSI).
# -Ntddi NTDDI_WIN10_VB builds at the Windows 10 2004 API floor.
param([string]$Ntddi = '')
$here = $PSScriptRoot
$repo = Resolve-Path (Join-Path $here '..\..')
. (Join-Path $here 'vcenv.ps1')
$out = Join-Path $repo "target\win-intl-harness$Ntddi"
New-Item -ItemType Directory -Force $out | Out-Null
Set-Location $out
$defs = @('/DNOMINMAX')
if ($Ntddi) { $defs += @("/DNTDDI_VERSION=$Ntddi", '/D_WIN32_WINNT=0x0A00', '/FIsdkddkver.h') }
$srcs = @(Join-Path $here 'harness.cc') + ('intl_icu.cc','intl_case_icu.cc','intl_datetime_icu.cc' | ForEach-Object { Join-Path $repo "crates\ibex2\src\bindings\$_" })
& cl /nologo /std:c++17 /EHsc /W4 /permissive- /O2 /utf-8 @defs @srcs /Fe:harness.exe /link icu.lib
"build exit=$LASTEXITCODE"
if ($LASTEXITCODE -eq 0) { & .\harness.exe; "run exit=$LASTEXITCODE" }
