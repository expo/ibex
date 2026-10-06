# vcvars64 import only (the vcvars half of C:\ExactTools\initialize-windows-native-env.ps1,
# whose second half requires an Exact Hermes profile this spike does not use).
$VsWhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
$VisualStudioRoot = & $VsWhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$VcVars = Join-Path $VisualStudioRoot.Trim() "VC\Auxiliary\Build\vcvars64.bat"
$lines = & $env:COMSPEC /d /s /c "call `"$VcVars`" >nul && set"
foreach ($l in $lines) { if ($l -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], "Process") } }
