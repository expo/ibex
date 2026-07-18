param(
  [ValidateSet("x64", "arm64")]
  [string]$Arch = "x64",
  [switch]$Force,
  [switch]$Source
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")
$builder = Join-Path $scriptDir "build-hermes-windows.ps1"
$builderDigest = (Get-FileHash -Algorithm SHA256 -LiteralPath $builder).Hash.ToLowerInvariant()
$identity = (& $builder -Arch $Arch -PrintIdentity | Select-Object -Last 1).Trim()
$tag = "hermes-$identity"
$asset = "hermes-windows-$Arch-$identity.zip"
$artifactRepo = if ($env:IBEX_HERMES_ARTIFACT_REPO) {
  $env:IBEX_HERMES_ARTIFACT_REPO
} else {
  "ccheever/ibex"
}
$targetRoot = Join-Path $repoRoot "tools\hermes\windows-$Arch"

function Test-InstallComplete {
  $required = @(
    "include\jsi\jsi.h",
    "include\jsi\jsi.cpp",
    "include\hermes\hermes.h",
    "include\hermes\Public\rtti.cpp",
    "lib\hermes.lib",
    "bin\hermesvm.dll",
    "bin\hermes.exe",
    "bin\hermesc.exe",
    "artifact.json"
  )
  foreach ($relative in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $targetRoot $relative))) {
      return $false
    }
  }
  $manifest = Get-Content -LiteralPath (Join-Path $targetRoot "artifact.json") -Raw |
    ConvertFrom-Json
  $manifestMatches = $manifest.sourceCommit.StartsWith($identity.Substring(0, 12)) -and
    $manifest.patchDigest -eq $identity.Substring($identity.Length - 12) -and
    $manifest.sourceBuildAuthorityDigest -eq $builderDigest -and
    $manifest.architecture -eq $Arch -and
    $manifest.configuration -eq "Release" -and
    $manifest.debugger -eq $false
  if (-not $manifestMatches) {
    return $false
  }
  if (Get-Command dumpbin -ErrorAction SilentlyContinue) {
    $exports = dumpbin /exports (Join-Path $targetRoot "bin\hermesvm.dll") | Out-String
    if ($exports -match 'CDPAgent|CDPDebugAPI') {
      return $false
    }
  }
  return $true
}

function Invoke-SourceBuild {
  Write-Host "Building the pinned patched Windows Hermes artifact from source."
  & $builder -Arch $Arch
  if ($LASTEXITCODE -ne 0) { throw "Windows Hermes source build failed" }
}

if ((Test-InstallComplete) -and -not $Force) {
  Write-Host "Patched Windows Hermes $identity is already installed at $targetRoot"
  exit 0
}

if ($Source -or $env:IBEX_HERMES_FORCE_BUILD -eq "1") {
  Invoke-SourceBuild
  exit 0
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
  "ibex-hermes-windows-" + [System.Guid]::NewGuid().ToString("N")
)
New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
try {
  $archive = Join-Path $tempRoot $asset
  $checksum = "$archive.sha256"
  $downloaded = $false
  if (Get-Command gh -ErrorAction SilentlyContinue) {
    gh auth status 2>$null
    if ($LASTEXITCODE -eq 0) {
      gh release download $tag --repo $artifactRepo --dir $tempRoot `
        --pattern $asset --pattern "$asset.sha256"
      $downloaded = $LASTEXITCODE -eq 0
    }
  }
  if (-not $downloaded) {
    $base = "https://github.com/$artifactRepo/releases/download/$tag"
    try {
      Invoke-WebRequest -Uri "$base/$asset" -OutFile $archive
      Invoke-WebRequest -Uri "$base/$asset.sha256" -OutFile $checksum
      $downloaded = $true
    }
    catch {
      Write-Warning "Prebuilt Windows Hermes $identity is unavailable: $($_.Exception.Message)"
    }
  }
  if (-not $downloaded) {
    Invoke-SourceBuild
    exit 0
  }

  $expected = ((Get-Content -LiteralPath $checksum -Raw).Trim() -split '\s+')[0].ToLowerInvariant()
  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
  if ($expected -ne $actual) {
    throw "Checksum mismatch for $asset (expected $expected, got $actual)"
  }

  $unpack = Join-Path $tempRoot "unpack"
  Expand-Archive -LiteralPath $archive -DestinationPath $unpack -Force
  $manifestPath = Join-Path $unpack "artifact.json"
  $dllPath = Join-Path $unpack "bin\hermesvm.dll"
  if (-not (Test-Path -LiteralPath $manifestPath) -or
      -not (Test-Path -LiteralPath $dllPath)) {
    throw "Downloaded Windows Hermes bundle has an incomplete shape"
  }
  $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
  if (-not $manifest.sourceCommit.StartsWith($identity.Substring(0, 12)) -or
      $manifest.patchDigest -ne $identity.Substring($identity.Length - 12) -or
      $manifest.sourceBuildAuthorityDigest -ne $builderDigest -or
      $manifest.architecture -ne $Arch -or
      $manifest.configuration -ne "Release" -or
      $manifest.debugger -ne $false) {
    throw "Downloaded Windows Hermes manifest does not match $identity/$Arch/Release"
  }
  $dllDigest = (Get-FileHash -Algorithm SHA256 -LiteralPath $dllPath).Hash.ToLowerInvariant()
  if ($dllDigest -ne $manifest.binarySha256) {
    throw "Downloaded Windows Hermes DLL does not match its manifest digest"
  }
  if (Get-Command dumpbin -ErrorAction SilentlyContinue) {
    $exports = dumpbin /exports $dllPath | Out-String
    if ($exports -notmatch 'ex_hermes_vm_current_package_id') {
      throw "Downloaded Windows Hermes DLL lacks the patched attribution export"
    }
    if ($exports -match 'CDPAgent|CDPDebugAPI') {
      throw "Downloaded Windows Hermes DLL is not a no-debugger build"
    }
  }

  Remove-Item -LiteralPath $targetRoot -Recurse -Force -ErrorAction SilentlyContinue
  New-Item -ItemType Directory -Force -Path $targetRoot | Out-Null
  Copy-Item -Path (Join-Path $unpack "*") -Destination $targetRoot -Recurse -Force
  Write-Host "Installed patched Windows Hermes $identity at $targetRoot"
}
finally {
  Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
