param(
  [Parameter(Mandatory = $true)]
  [string]$OutputArchive
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = Split-Path -Parent $PSScriptRoot
$versionText = Get-Content -LiteralPath (Join-Path $PSScriptRoot "hermes-version.sh") -Raw
$pin = [regex]::Match($versionText, 'IBEX_HERMES_VANILLA_SOURCE_COMMIT="\$\{IBEX_HERMES_VANILLA_SOURCE_COMMIT:-([0-9a-f]{40})\}"')
if (-not $pin.Success) { throw "Cannot read vanilla Hermes source pin" }
$commit = $pin.Groups[1].Value
$target = "x86_64-pc-windows-msvc"

& (Join-Path $PSScriptRoot "build-hermes-windows-vanilla.ps1") -Arch x64 -Ref $commit
if ($LASTEXITCODE -ne 0) { throw "Base Windows Hermes build failed" }

$cacheRoot = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA "Exact\hermes2-windows-vanilla"))
$cacheDir = [IO.Path]::GetFullPath((Join-Path $cacheRoot "$commit-x64"))
$buildDir = Join-Path $cacheDir "build"
$bundleDir = Join-Path $cacheDir "release-bundle"

cmake --build $buildDir --target hermesvmlean_a --parallel 8
if ($LASTEXITCODE -ne 0) { throw "Lean Windows Hermes VM build failed" }

if (Test-Path -LiteralPath $bundleDir) {
  Remove-Item -LiteralPath $bundleDir -Recurse -Force
}
$binDir = Join-Path $bundleDir "bin"
$includeDir = Join-Path $bundleDir "include"
$libDir = Join-Path $bundleDir "lib"
New-Item -ItemType Directory -Force -Path $binDir, $includeDir, $libDir | Out-Null

$installDir = Join-Path $repoRoot "tools\hermes-vanilla\windows-x64"
Copy-Item -LiteralPath (Join-Path $repoRoot "tools\hermes-vanilla\hermesc-windows-x64.exe") `
  -Destination (Join-Path $binDir "hermesc.exe")
Copy-Item -Path (Join-Path $installDir "hermes-headers\*") -Destination $includeDir -Recurse
Copy-Item -LiteralPath (Join-Path $cacheDir "source\LICENSE") -Destination (Join-Path $bundleDir "LICENSE.hermes")

foreach ($name in @("hermesvm_a.lib", "hermesvmlean_a.lib", "jsi.lib", "boost_context.lib")) {
  $found = @(Get-ChildItem -LiteralPath $buildDir -Recurse -File -Filter $name)
  if ($found.Count -ne 1) { throw "Expected exactly one $name, found $($found.Count)" }
  Copy-Item -LiteralPath $found[0].FullName -Destination (Join-Path $libDir $name)
}

$receiptArgs = @(
  (Join-Path $PSScriptRoot "hermes-input-receipt.mjs"),
  $bundleDir,
  "--target=$target",
  "--profile=release",
  "--engine-archive=lib/hermesvm_a.lib",
  "--lean-engine-archive=lib/hermesvmlean_a.lib",
  "--build-flag=-DCMAKE_BUILD_TYPE=Release",
  "--build-flag=-DHERMES_ENABLE_DEBUGGER=OFF",
  "--build-flag=-DHERMES_ENABLE_INTL=OFF",
  "--build-flag=-DHERMES_ENABLE_WIN10_ICU_FALLBACK=ON",
  "--build-flag=-DHERMES_BUILD_APPLE_FRAMEWORK=OFF",
  "--build-flag=-DHERMES_BUILD_SHARED_JSI=OFF",
  "--build-flag=-DHERMES_ENABLE_TEST_SUITE=OFF",
  "--build-flag=-DHERMES_MSVC_MP=OFF",
  "--link-directive=rustc-link-search=native=lib",
  "--link-directive=rustc-link-lib=static=hermesvm_a",
  "--link-directive=rustc-link-lib=static=jsi",
  "--link-directive=rustc-link-lib=static=boost_context",
  "--link-directive=rustc-link-lib=icuuc",
  "--link-directive=rustc-link-lib=icuin",
  "--link-directive=rustc-link-lib=dbghelp",
  "--link-directive=rustc-link-lib=version",
  "--link-directive=rustc-link-lib=psapi",
  "--link-directive=rustc-link-lib=winmm"
)
& node @receiptArgs
if ($LASTEXITCODE -ne 0) { throw "Windows receipt generation failed" }

& python (Join-Path $PSScriptRoot "package-hermes-vanilla-release.py") $bundleDir $OutputArchive
if ($LASTEXITCODE -ne 0) { throw "Windows deterministic packaging failed" }
Write-Host "Built $OutputArchive from $commit"
