param(
  [string]$Version = "0.71.1",
  [ValidateSet("x64", "arm64", "x86")]
  [string]$Arch = "x64",
  [switch]$Force
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")
$targetRoot = Join-Path $repoRoot "tools\hermes\windows-$Arch"
$includeDir = Join-Path $targetRoot "include"
$libDir = Join-Path $targetRoot "lib"
$binDir = Join-Path $targetRoot "bin"

$runtimeDlls = @(
  "hermes.dll",
  "icuuc.dll",
  "icuin.dll",
  "MSVCP140_APP.dll",
  "VCRUNTIME140_APP.dll",
  "VCRUNTIME140_1_APP.dll"
)

function Test-HermesInstallComplete {
  if (-not (Test-Path $includeDir)) { return $false }
  if (-not (Test-Path (Join-Path $libDir "hermes.lib"))) { return $false }
  if (-not (Test-Path (Join-Path $binDir "hermesc.exe"))) { return $false }
  foreach ($dll in $runtimeDlls) {
    if (-not (Test-Path (Join-Path $binDir $dll))) { return $false }
  }
  return $true
}

function Find-FirstExistingFile {
  param([string[]]$Candidates)

  foreach ($candidate in $Candidates) {
    if (Test-Path -LiteralPath $candidate) {
      return $candidate
    }
  }
  return $null
}

function Find-AppRuntimeDll {
  param([string]$Name)

  $lower = $Name.ToLowerInvariant()
  $archToken = if ($Arch -eq "x64") { "x64" } elseif ($Arch -eq "arm64") { "arm64" } else { "x86" }
  $winsxsToken = if ($Arch -eq "x64") { "amd64" } elseif ($Arch -eq "arm64") { "arm64" } else { "x86" }

  $directCandidates = @(
    (Join-Path $env:SystemRoot "System32\$Name"),
    (Join-Path $env:SystemRoot "System32\$lower"),
    "C:\Program Files (x86)\Microsoft SDKs\UWPNuGetPackages\microsoft.net.native.compiler\1.7.6\tools\$archToken\ilc\lib\MSCRT\$lower",
    "C:\Program Files (x86)\Microsoft SDKs\UWPNuGetPackages\microsoft.net.native.compiler\1.7.6\tools\$archToken\ilc\lib\MSCRT\$Name"
  )
  $direct = Find-FirstExistingFile $directCandidates
  if ($direct) { return $direct }

  $vclibsRoot = "C:\Program Files\WindowsApps"
  if (Test-Path $vclibsRoot) {
    $vclibs = Get-ChildItem -LiteralPath $vclibsRoot -Directory -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -like "Microsoft.VCLibs.140.00_*_${archToken}__8wekyb3d8bbwe" } |
      Sort-Object Name -Descending
    foreach ($dir in $vclibs) {
      $candidate = Find-FirstExistingFile @(
        (Join-Path $dir.FullName $lower),
        (Join-Path $dir.FullName $Name)
      )
      if ($candidate) { return $candidate }
    }
  }

  $winsxsRoot = Join-Path $env:SystemRoot "WinSxS"
  if (Test-Path $winsxsRoot) {
    $winsxs = Get-ChildItem -LiteralPath $winsxsRoot -Directory -Filter "${winsxsToken}_userexperience-core_*" -ErrorAction SilentlyContinue |
      Sort-Object Name -Descending
    foreach ($dir in $winsxs) {
      $candidate = Find-FirstExistingFile @(
        (Join-Path $dir.FullName "Core\$lower"),
        (Join-Path $dir.FullName "Core\$Name")
      )
      if ($candidate) { return $candidate }
    }
  }

  return $null
}

function Copy-AppRuntimeDll {
  param([string]$Name)

  $source = Find-AppRuntimeDll $Name
  if (-not $source) {
    throw "Could not find Windows runtime dependency $Name. Install Microsoft.VCLibs.140.00 for $Arch, then rerun this script."
  }

  Copy-Item -LiteralPath $source -Destination (Join-Path $binDir $Name) -Force
}

function Copy-HermesCompiler {
  param([string]$ExtractDir)

  # ReactNative.Hermes.Windows 0.71.x ships a Hermes CLI only in the x86 tools
  # folder. Hermes bytecode is architecture-independent, so this is still the
  # right compiler for the x64/arm64 runtimes as long as its HBC version matches
  # the runtime headers.
  $candidates = @(
    (Join-Path $ExtractDir "tools\native\release\$Arch\hermes.exe"),
    (Join-Path $ExtractDir "tools\native\debug\$Arch\hermes.exe"),
    (Join-Path $ExtractDir "tools\native\release\x86\hermes.exe"),
    (Join-Path $ExtractDir "tools\native\debug\x86\hermes.exe")
  )
  $compiler = Find-FirstExistingFile $candidates
  if (-not $compiler) {
    Write-Warning "Hermes compiler not found in ReactNative.Hermes.Windows $Version. Native HBC startup will remain disabled."
    return
  }

  Copy-Item -LiteralPath $compiler -Destination (Join-Path $binDir "hermesc.exe") -Force
  Copy-Item -LiteralPath $compiler -Destination (Join-Path $binDir "hermes.exe") -Force
}

if ((Test-HermesInstallComplete) -and -not $Force) {
  Write-Host "Windows Hermes already installed at $targetRoot"
  exit 0
}

New-Item -ItemType Directory -Force -Path $includeDir, $libDir, $binDir | Out-Null

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("exact-hermes-" + [System.Guid]::NewGuid().ToString("N"))
$packagePath = Join-Path $tempRoot "ReactNative.Hermes.Windows.$Version.nupkg"
$zipPath = Join-Path $tempRoot "ReactNative.Hermes.Windows.$Version.zip"
$extractDir = Join-Path $tempRoot "pkg"
New-Item -ItemType Directory -Force -Path $tempRoot, $extractDir | Out-Null

try {
  $uri = "https://www.nuget.org/api/v2/package/ReactNative.Hermes.Windows/$Version"
  Write-Host "Downloading $uri"
  Invoke-WebRequest -Uri $uri -OutFile $packagePath
  Copy-Item -Path $packagePath -Destination $zipPath -Force
  Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

  $headers = Join-Path $extractDir "build\native\include"
  if (-not (Test-Path $headers)) {
    throw "Hermes headers not found in package at $headers"
  }
  Copy-Item -Path (Join-Path $headers "*") -Destination $includeDir -Recurse -Force

  $nativeCandidates = @(
    (Join-Path $extractDir "lib\native\release\$Arch"),
    (Join-Path $extractDir "lib\native\debug\$Arch")
  )
  $nativeDir = $nativeCandidates | Where-Object { Test-Path (Join-Path $_ "hermes.lib") } | Select-Object -First 1
  if (-not $nativeDir) {
    throw "hermes.lib not found for $Arch in ReactNative.Hermes.Windows $Version"
  }

  Copy-Item -Path (Join-Path $nativeDir "hermes.lib") -Destination $libDir -Force
  if (Test-Path (Join-Path $nativeDir "hermes.dll")) {
    Copy-Item -Path (Join-Path $nativeDir "hermes.dll") -Destination $binDir -Force
    Copy-Item -Path (Join-Path $nativeDir "hermes.dll") -Destination $libDir -Force
  }
  if (Test-Path (Join-Path $nativeDir "hermes.pdb")) {
    Copy-Item -Path (Join-Path $nativeDir "hermes.pdb") -Destination $binDir -Force
  }
  Copy-HermesCompiler $extractDir

  Copy-AppRuntimeDll "icuuc.dll"
  Copy-AppRuntimeDll "icuin.dll"
  Copy-AppRuntimeDll "MSVCP140_APP.dll"
  Copy-AppRuntimeDll "VCRUNTIME140_APP.dll"
  Copy-AppRuntimeDll "VCRUNTIME140_1_APP.dll"

  Write-Host "Installed Windows Hermes headers/libs at $targetRoot"
  Write-Host "Installed Hermes compiler at $(Join-Path $binDir "hermesc.exe") when available."
}
finally {
  Remove-Item -Recurse -Force $tempRoot -ErrorAction SilentlyContinue
}
