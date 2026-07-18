param(
  [ValidateSet("x64", "arm64")]
  [string]$Arch = "x64",
  [string]$Ref = "",
  [switch]$Debug,
  [switch]$Clean,
  [switch]$PrintIdentity
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")
$versionScript = Join-Path $scriptDir "hermes-version.sh"
$versionText = Get-Content -LiteralPath $versionScript -Raw
if (-not $Ref) {
  $match = [regex]::Match(
    $versionText,
    'IBEX_HERMES_SOURCE_COMMIT="\$\{IBEX_HERMES_SOURCE_COMMIT:-([0-9a-f]{40})\}"'
  )
  if (-not $match.Success) {
    throw "Could not resolve the pinned Hermes commit from scripts/hermes-version.sh"
  }
  $Ref = $match.Groups[1].Value
}

function Get-PatchDigest {
  $lines = @()
  $patches = Get-ChildItem -LiteralPath (Join-Path $repoRoot "patches\hermes") -Filter "*.patch" |
    Sort-Object Name
  foreach ($patch in $patches) {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $patch.FullName).Hash.ToLowerInvariant()
    $lines += "$hash  patches/hermes/$($patch.Name)"
  }
  $payload = if ($lines.Count -eq 0) { "" } else { ($lines -join "`n") + "`n" }
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $digest = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($payload))
  }
  finally {
    $sha.Dispose()
  }
  return ([Convert]::ToHexString($digest).ToLowerInvariant()).Substring(0, 12)
}

function Find-OneFile {
  param(
    [string]$Root,
    [string]$Name,
    [string]$Purpose
  )
  $matches = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Filter $Name)
  if ($matches.Count -eq 0) {
    throw "Could not find $Purpose ($Name) under $Root"
  }
  $release = @($matches | Where-Object { $_.FullName -match '[\\/]Release[\\/]' })
  return $(if ($release.Count -gt 0) { $release[0] } else { $matches[0] })
}

function Convert-ToBashPath {
  param([string]$Path)
  $full = [System.IO.Path]::GetFullPath($Path)
  if ($full -match '^([A-Za-z]):\\(.*)$') {
    return "/$($matches[1].ToLowerInvariant())/$($matches[2].Replace('\', '/'))"
  }
  return $full.Replace('\', '/')
}

$patchDigest = Get-PatchDigest
$commitKey = if ($Ref -match '^[0-9a-f]{40}$') { $Ref.Substring(0, 12) } else { $Ref }
$identity = "$commitKey-$patchDigest"
if ($PrintIdentity) {
  Write-Output $identity
  exit 0
}
$profile = if ($Debug) { "debug" } else { "release" }
$cacheRoot = Join-Path $env:LOCALAPPDATA "Exact\hermes-windows"
$cacheDir = Join-Path $cacheRoot "$commitKey-$profile-p$patchDigest-$Arch"
$sourceDir = Join-Path $cacheRoot "hermes-src"
$buildDir = Join-Path $cacheDir "build"
$installDir = Join-Path $cacheDir "install"
$targetRoot = Join-Path $repoRoot "tools\hermes\windows-$Arch"

if ($Clean) {
  Remove-Item -LiteralPath $cacheDir -Recurse -Force -ErrorAction SilentlyContinue
  Write-Host "Cleaned Windows Hermes cache: $cacheDir"
  exit 0
}

if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw "git is required" }
if (-not (Get-Command cmake -ErrorAction SilentlyContinue)) { throw "cmake is required" }
if (-not (Get-Command bash -ErrorAction SilentlyContinue)) { throw "Git Bash is required" }

New-Item -ItemType Directory -Force -Path $cacheRoot | Out-Null
if (-not (Test-Path (Join-Path $sourceDir ".git"))) {
  git clone https://github.com/facebook/hermes.git $sourceDir
  if ($LASTEXITCODE -ne 0) { throw "Failed to clone Hermes" }
}

git -C $sourceDir fetch origin --tags
if ($LASTEXITCODE -ne 0) { throw "Failed to fetch Hermes" }
if ($Ref -match '^[0-9a-f]{40}$') {
  git -C $sourceDir cat-file -e "$Ref^{commit}" 2>$null
  if ($LASTEXITCODE -ne 0) {
    git -C $sourceDir fetch origin $Ref
    if ($LASTEXITCODE -ne 0) { throw "Failed to fetch pinned Hermes commit $Ref" }
  }
}
git -C $sourceDir checkout --force $Ref
if ($LASTEXITCODE -ne 0) { throw "Failed to check out Hermes $Ref" }
git -C $sourceDir clean -fdq
if ($LASTEXITCODE -ne 0) { throw "Failed to clean the Hermes checkout" }

$applyScriptUnix = Convert-ToBashPath (Join-Path $scriptDir "apply-hermes-patches.sh")
$sourceDirUnix = Convert-ToBashPath $sourceDir
& bash $applyScriptUnix $sourceDirUnix
if ($LASTEXITCODE -ne 0) { throw "Failed to apply the checked Hermes patch stack" }

Remove-Item -LiteralPath $buildDir, $installDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $buildDir, $installDir | Out-Null
$cmakeArch = if ($Arch -eq "arm64") { "ARM64" } else { "x64" }
$debuggerFlag = if ($Debug) { "ON" } else { "OFF" }
cmake -S $sourceDir -B $buildDir -G "Visual Studio 17 2022" -A $cmakeArch `
  "-DHERMES_ENABLE_DEBUGGER:BOOL=$debuggerFlag" `
  -DHERMES_ENABLE_INTL=OFF `
  -DHERMES_ENABLE_WIN10_ICU_FALLBACK=ON `
  -DHERMES_BUILD_APPLE_FRAMEWORK=OFF `
  -DHERMES_BUILD_SHARED_JSI=OFF
if ($LASTEXITCODE -ne 0) { throw "Hermes CMake configuration failed" }
$cmakeCache = Join-Path $buildDir "CMakeCache.txt"
$expectedDebuggerCache = "HERMES_ENABLE_DEBUGGER:BOOL=$debuggerFlag"
$debuggerCacheEntries = @(
  Get-Content -LiteralPath $cmakeCache | Where-Object {
    $_ -match '^HERMES_ENABLE_DEBUGGER:'
  }
)
if ($debuggerCacheEntries.Count -ne 1 -or
    $debuggerCacheEntries[0] -ne $expectedDebuggerCache) {
  throw "Hermes CMake debugger profile drifted (expected $expectedDebuggerCache, got $($debuggerCacheEntries -join ', '))"
}
cmake --build $buildDir --config Release --target hermesvm hermes hermesc -- /m
if ($LASTEXITCODE -ne 0) { throw "Hermes Windows build failed" }

$hermesDll = Find-OneFile $buildDir "hermesvm.dll" "Hermes runtime DLL"
$hermesLib = Find-OneFile $buildDir "hermesvm.lib" "Hermes import library"
$hermesExe = Find-OneFile $buildDir "hermes.exe" "Hermes CLI"
$hermescExe = Find-OneFile $buildDir "hermesc.exe" "Hermes compiler"
if (-not $Debug) {
  if (-not (Get-Command dumpbin -ErrorAction SilentlyContinue)) {
    throw "dumpbin is required to attest the no-debugger Windows Hermes profile"
  }
  $hermesExports = dumpbin /exports $hermesDll.FullName | Out-String
  if ($hermesExports -match 'AsyncDebuggerAPI') {
    throw "No-debugger Windows Hermes build still exports AsyncDebuggerAPI"
  }
}

$includeDir = Join-Path $installDir "include"
$libDir = Join-Path $installDir "lib"
$binDir = Join-Path $installDir "bin"
New-Item -ItemType Directory -Force -Path $includeDir, $libDir, $binDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $includeDir "jsi"), (Join-Path $includeDir "hermes") | Out-Null
Copy-Item -Path (Join-Path $sourceDir "API\jsi\jsi\*") -Destination (Join-Path $includeDir "jsi") -Recurse -Force
Copy-Item -Path (Join-Path $sourceDir "API\hermes\*") -Destination (Join-Path $includeDir "hermes") -Recurse -Force
Copy-Item -Path (Join-Path $sourceDir "public\hermes\Public") -Destination (Join-Path $includeDir "hermes") -Recurse -Force
Copy-Item -LiteralPath $hermesDll.FullName -Destination (Join-Path $binDir "hermesvm.dll") -Force
Copy-Item -LiteralPath $hermesDll.FullName -Destination (Join-Path $libDir "hermesvm.dll") -Force
Copy-Item -LiteralPath $hermesLib.FullName -Destination (Join-Path $libDir "hermesvm.lib") -Force
# Keep build.rs's historical Windows default while preserving the upstream
# hermesvm import-library name for explicit consumers.
Copy-Item -LiteralPath $hermesLib.FullName -Destination (Join-Path $libDir "hermes.lib") -Force
Copy-Item -LiteralPath $hermesExe.FullName -Destination (Join-Path $binDir "hermes.exe") -Force
Copy-Item -LiteralPath $hermescExe.FullName -Destination (Join-Path $binDir "hermesc.exe") -Force

$actualCommit = (git -C $sourceDir rev-parse HEAD).Trim()
$manifest = [ordered]@{
  schema = "ibex/hermes-build/1"
  sourceCommit = $actualCommit
  patchDigest = $patchDigest
  sourceBuildAuthorityDigest = (Get-FileHash -Algorithm SHA256 -LiteralPath $MyInvocation.MyCommand.Path).Hash.ToLowerInvariant()
  architecture = $Arch
  configuration = "Release"
  debugger = [bool]$Debug
  binarySha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $binDir "hermesvm.dll")).Hash.ToLowerInvariant()
}
$manifest | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $installDir "artifact.json") -Encoding utf8NoBOM

Remove-Item -LiteralPath $targetRoot -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $targetRoot | Out-Null
Copy-Item -Path (Join-Path $installDir "*") -Destination $targetRoot -Recurse -Force

Write-Host "Installed patched Windows Hermes at $targetRoot"
Write-Host "  commit:   $actualCommit"
Write-Host "  patches:  $patchDigest"
Write-Host "  debugger: $([bool]$Debug)"
