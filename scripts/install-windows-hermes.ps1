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
$versionScript = Join-Path $scriptDir "hermes-version.sh"

function Get-PatchStackDigestHex {
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
  return [Convert]::ToHexString($digest).ToLowerInvariant()
}

function Get-FileSuffixDigestHex {
  param(
    [string]$Path,
    [string]$Marker
  )
  $bytes = [System.IO.File]::ReadAllBytes($Path)
  $markerBytes = [System.Text.Encoding]::UTF8.GetBytes($Marker)
  $start = -1
  for ($index = 0; $index -le $bytes.Length - $markerBytes.Length; $index++) {
    $matches = $true
    for ($offset = 0; $offset -lt $markerBytes.Length; $offset++) {
      if ($bytes[$index + $offset] -ne $markerBytes[$offset]) {
        $matches = $false
        break
      }
    }
    if ($matches) {
      $start = $index
      break
    }
  }
  if ($start -lt 0) {
    throw "Could not find reviewed authority marker '$Marker' in $Path"
  }
  $suffix = [byte[]]::new($bytes.Length - $start)
  [System.Array]::Copy($bytes, $start, $suffix, 0, $suffix.Length)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $digest = $sha.ComputeHash($suffix)
  }
  finally {
    $sha.Dispose()
  }
  return [Convert]::ToHexString($digest).ToLowerInvariant()
}

$builderDigest = (Get-FileHash -Algorithm SHA256 -LiteralPath $builder).Hash.ToLowerInvariant()
$installerDigest = (
  Get-FileHash -Algorithm SHA256 -LiteralPath $MyInvocation.MyCommand.Path
).Hash.ToLowerInvariant()
$patchStackDigestHex = Get-PatchStackDigestHex
$patchApplicationAuthorityDigest = (
  Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $scriptDir "apply-hermes-patches.sh")
).Hash.ToLowerInvariant()
$patchIdentityAuthorityDigest = Get-FileSuffixDigestHex `
  -Path $versionScript `
  -Marker "ibex_sha256() {`n"
$versionText = Get-Content -LiteralPath $versionScript -Raw
$sourceVersionMatch = [regex]::Match(
  $versionText,
  'IBEX_HERMES_VERSION="\$\{IBEX_HERMES_VERSION:-([^}]+)\}"'
)
$sourceCommitMatch = [regex]::Match(
  $versionText,
  'IBEX_HERMES_SOURCE_COMMIT="\$\{IBEX_HERMES_SOURCE_COMMIT:-([0-9a-f]{40})\}"'
)
if (-not $sourceVersionMatch.Success -or -not $sourceCommitMatch.Success) {
  throw "Could not resolve the reviewed Hermes source identity from scripts/hermes-version.sh"
}
$reviewedSourceVersion = $sourceVersionMatch.Groups[1].Value
$reviewedSourceRef = "$reviewedSourceVersion-stable"
$reviewedSourceCommit = $sourceCommitMatch.Groups[1].Value
$identity = (& $builder -Arch $Arch -PrintIdentity | Select-Object -Last 1).Trim()
$builderBlob = (& git -C $repoRoot hash-object `
  --path=scripts/build-hermes-windows.ps1 scripts/build-hermes-windows.ps1).Trim()
$installerBlob = (& git -C $repoRoot hash-object `
  --path=scripts/install-windows-hermes.ps1 scripts/install-windows-hermes.ps1).Trim()
if ($LASTEXITCODE -ne 0 -or
    $builderBlob -notmatch '^[0-9a-f]{40}$' -or
    $installerBlob -notmatch '^[0-9a-f]{40}$') {
  throw "Could not derive the reviewed Windows Hermes builder/installer identity"
}
$assetKey = "$identity-a$($patchApplicationAuthorityDigest.Substring(0, 12))-i$($patchIdentityAuthorityDigest.Substring(0, 12))-bw$($builderBlob.Substring(0, 12))-iw$($installerBlob.Substring(0, 12))"
$tag = "hermes-$identity"
$asset = "hermes-windows-$Arch-$assetKey.zip"
$artifactRepo = if ($env:IBEX_HERMES_ARTIFACT_REPO) {
  $env:IBEX_HERMES_ARTIFACT_REPO
} else {
  "expo/ibex"
}
$reviewedAttestationRepo = "expo/ibex"
$reviewedAttestationWorkflow = "expo/ibex/.github/workflows/hermes-artifacts.yml"
$reviewedAttestationSourceRef = "refs/heads/main"
$targetRoot = Join-Path $repoRoot "tools\hermes\windows-$Arch"
$cacheRoot = Join-Path $env:LOCALAPPDATA "Exact\hermes-windows"

function Test-ExactPropertyNames {
  param(
    [object]$Value,
    [string[]]$Expected
  )
  if ($null -eq $Value) { return $false }
  $actualNames = @($Value.PSObject.Properties.Name | Sort-Object)
  $expectedNames = @($Expected | Sort-Object)
  return $actualNames.Count -eq $expectedNames.Count -and
    ($actualNames -join "`n") -ceq ($expectedNames -join "`n")
}

# Use the same stable OS file lock as build-hermes-windows.ps1 whenever this
# installer reads or replaces the shared tools/hermes/windows-$Arch output.
# The installer never holds it while delegating to the source builder, which
# prevents self-deadlock while preserving a single publication domain.
# @ref LLP 0013#upstream-tracking-and-re-derivation — prebuilt installation
# joins the source builder's mutable artifact-publication boundary.
function Enter-HermesSourceBuildLock {
  param([string]$Entrypoint)

  $lockPath = if ($env:IBEX_HERMES_WINDOWS_BUILD_LOCK_FILE) {
    $env:IBEX_HERMES_WINDOWS_BUILD_LOCK_FILE
  } else {
    Join-Path $cacheRoot "source-build.lock"
  }
  $lockDirectory = Split-Path -Parent $lockPath
  if ($lockDirectory) {
    New-Item -ItemType Directory -Force -Path $lockDirectory | Out-Null
  }

  $timeoutSeconds = 14400
  if ($env:IBEX_HERMES_WINDOWS_BUILD_LOCK_TIMEOUT_SECONDS) {
    $parsedTimeout = 0
    if (-not [int]::TryParse(
        $env:IBEX_HERMES_WINDOWS_BUILD_LOCK_TIMEOUT_SECONDS,
        [ref]$parsedTimeout
      ) -or $parsedTimeout -lt 1) {
      throw "IBEX_HERMES_WINDOWS_BUILD_LOCK_TIMEOUT_SECONDS must be a positive integer"
    }
    $timeoutSeconds = $parsedTimeout
  }

  $wait = [System.Diagnostics.Stopwatch]::StartNew()
  $announcedWait = $false
  while ($true) {
    try {
      $stream = [System.IO.File]::Open(
        $lockPath,
        [System.IO.FileMode]::OpenOrCreate,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::None
      )
      try {
        $owner = "pid=$PID`nentrypoint=$Entrypoint`n"
        $ownerBytes = [System.Text.Encoding]::UTF8.GetBytes($owner)
        $stream.SetLength(0)
        $stream.Write($ownerBytes, 0, $ownerBytes.Length)
        $stream.Flush($true)
      }
      catch {
        $stream.Dispose()
        throw
      }
      Write-Host "[lock] Acquired Windows Hermes source-build lock for $Entrypoint."
      return $stream
    }
    catch [System.IO.IOException] {
      if ($wait.Elapsed.TotalSeconds -ge $timeoutSeconds) {
        throw "Timed out after $timeoutSeconds seconds waiting for Windows Hermes source-build lock $lockPath"
      }
      if (-not $announcedWait) {
        Write-Host "[lock] Waiting for the Windows Hermes source-build lock at $lockPath..."
        $announcedWait = $true
      }
      Start-Sleep -Milliseconds 250
    }
  }
}

function Exit-HermesSourceBuildLock {
  param([System.IO.FileStream]$Lock)

  if ($null -ne $Lock) {
    $Lock.Dispose()
    Write-Host "[lock] Released Windows Hermes source-build lock."
  }
}

function Test-ArtifactDirectoryComplete {
  param([string]$Root)

  $required = @(
    "include\jsi\jsi.h",
    "include\jsi\jsi.cpp",
    "include\hermes\hermes.h",
    "include\hermes\Public\rtti.cpp",
    "lib\hermes.lib",
    "lib\hermesvm.lib",
    "bin\hermesvm.dll",
    "bin\hermes.exe",
    "bin\hermesc.exe",
    "bin\hermes-profile-provenance.json",
    "artifact.json"
  )
  foreach ($relative in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $Root $relative))) {
      return $false
    }
  }
  try {
    $manifest = Get-Content -LiteralPath (Join-Path $Root "artifact.json") -Raw |
      ConvertFrom-Json
    $receipt = Get-Content -LiteralPath (Join-Path $Root "bin\hermes-profile-provenance.json") -Raw |
      ConvertFrom-Json
    $dllPath = Join-Path $Root "bin\hermesvm.dll"
    $linkPath = Join-Path $Root "lib\hermes.lib"
    $dllDigest = (Get-FileHash -Algorithm SHA256 -LiteralPath $dllPath).Hash.ToLowerInvariant()
    $linkDigest = (Get-FileHash -Algorithm SHA256 -LiteralPath $linkPath).Hash.ToLowerInvariant()
    $targetArchitecture = if ($Arch -eq "arm64") { "aarch64" } else { "x86_64" }
    if (-not (Test-ExactPropertyNames $receipt @(
          "artifact", "linkArtifact", "origin", "profileId", "schema", "targetVariant"
        )) -or
        -not (Test-ExactPropertyNames $receipt.artifact @(
          "binaryDigest", "fileName", "targetArchitecture"
        )) -or
        -not (Test-ExactPropertyNames $receipt.linkArtifact @(
          "binaryDigest", "fileName", "targetArchitecture"
        )) -or
        -not (Test-ExactPropertyNames $receipt.origin @(
          "configuration", "debugger", "kind", "reviewedProfileIdentity"
        )) -or
        -not (Test-ExactPropertyNames $receipt.origin.reviewedProfileIdentity @(
          "artifact",
          "patchApplicationAuthorityDigest",
          "patchIdentityAuthorityDigest",
          "patchStackDigest",
          "sourceBuildAuthorityDigest",
          "sourceCommit",
          "sourceInstallerAuthorityDigest",
          "sourceRef",
          "sourceVersion"
        ))) {
      return $false
    }
    $reviewed = $receipt.origin.reviewedProfileIdentity
    $profileMatches = $manifest.schema -eq "ibex/hermes-build/1" -and
      $manifest.sourceCommit -eq $reviewedSourceCommit -and
      $manifest.patchDigest -eq $identity.Substring($identity.Length - 12) -and
      $manifest.sourceBuildAuthorityDigest -eq $builderDigest -and
      $manifest.architecture -eq $Arch -and
      $manifest.configuration -eq "Release" -and
      $manifest.debugger -eq $false -and
      $manifest.binarySha256 -eq $dllDigest -and
      $receipt.schema -eq "ibex/hermes-profile-provenance-receipt/2" -and
      $receipt.profileId -eq "windows-source-patched" -and
      $receipt.targetVariant -eq "windows" -and
      $receipt.artifact.binaryDigest -eq "sha256-$dllDigest" -and
      $receipt.artifact.fileName -eq "hermesvm.dll" -and
      $receipt.artifact.targetArchitecture -eq $targetArchitecture -and
      $receipt.linkArtifact.binaryDigest -eq "sha256-$linkDigest" -and
      $receipt.linkArtifact.fileName -eq "hermes.lib" -and
      $receipt.linkArtifact.targetArchitecture -eq $targetArchitecture -and
      $receipt.origin.configuration -eq "Release" -and
      $receipt.origin.debugger -eq $false -and
      $receipt.origin.kind -eq "source-patched-build" -and
      $reviewed.artifact -eq "facebook/hermes" -and
      $reviewed.patchApplicationAuthorityDigest -eq "sha256-$patchApplicationAuthorityDigest" -and
      $reviewed.patchIdentityAuthorityDigest -eq "sha256-$patchIdentityAuthorityDigest" -and
      $reviewed.patchStackDigest -eq "sha256-$patchStackDigestHex" -and
      $manifest.patchDigest -eq $patchStackDigestHex.Substring(0, 12) -and
      $reviewed.sourceBuildAuthorityDigest -eq "sha256-$builderDigest" -and
      $reviewed.sourceCommit -eq $reviewedSourceCommit -and
      $reviewed.sourceInstallerAuthorityDigest -eq "sha256-$installerDigest" -and
      $reviewed.sourceRef -eq $reviewedSourceRef -and
      $reviewed.sourceVersion -eq $reviewedSourceVersion
    if (-not $profileMatches) {
      return $false
    }
    if (Get-Command dumpbin -ErrorAction SilentlyContinue) {
      $exports = dumpbin /exports $dllPath | Out-String
      if ($exports -match 'CDPAgent|CDPDebugAPI') {
        return $false
      }
    }
    return $true
  }
  catch {
    return $false
  }
}

function Test-InstallComplete {
  return Test-ArtifactDirectoryComplete $targetRoot
}

function Invoke-SourceBuild {
  Write-Host "Building the pinned patched Windows Hermes artifact from source."
  & $builder -Arch $Arch
  if ($LASTEXITCODE -ne 0) { throw "Windows Hermes source build failed" }
}

function Test-ReviewedBuildProvenance {
  param([string]$Archive)

  if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    Write-Warning "GitHub CLI is unavailable; refusing an unattested prebuilt Windows Hermes bundle."
    return $false
  }
  gh auth status 2>$null
  if ($LASTEXITCODE -ne 0) {
    Write-Warning "Authenticated GitHub CLI is required to verify Windows Hermes build provenance."
    return $false
  }
  gh attestation verify $Archive `
    --repo $reviewedAttestationRepo `
    --signer-workflow $reviewedAttestationWorkflow `
    --source-ref $reviewedAttestationSourceRef `
    --deny-self-hosted-runners | Out-Null
  if ($LASTEXITCODE -ne 0) {
    Write-Warning "GitHub build-provenance verification failed for $asset."
    return $false
  }
  Write-Host "Verified GitHub build provenance for $asset."
  return $true
}

$installCheckLock = Enter-HermesSourceBuildLock "install-windows-hermes-check-$Arch"
try {
  $installComplete = Test-InstallComplete
}
finally {
  Exit-HermesSourceBuildLock $installCheckLock
}
if ($installComplete -and -not $Force) {
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
  if ($downloaded -and -not (Test-ReviewedBuildProvenance $archive)) {
    $downloaded = $false
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
  $dllPath = Join-Path $unpack "bin\hermesvm.dll"
  if (-not (Test-ArtifactDirectoryComplete $unpack)) {
    throw "Downloaded Windows Hermes bundle does not match the reviewed source profile"
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

  $publishLock = Enter-HermesSourceBuildLock "install-windows-hermes-publish-$Arch"
  try {
    if (-not $Force -and (Test-InstallComplete)) {
      Write-Host "Patched Windows Hermes $identity was installed by another process at $targetRoot"
    }
    else {
      Remove-Item -LiteralPath $targetRoot -Recurse -Force -ErrorAction SilentlyContinue
      New-Item -ItemType Directory -Force -Path $targetRoot | Out-Null
      Copy-Item -Path (Join-Path $unpack "*") -Destination $targetRoot -Recurse -Force
      Write-Host "Installed patched Windows Hermes $identity at $targetRoot"
    }
  }
  finally {
    Exit-HermesSourceBuildLock $publishLock
  }
}
finally {
  Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}
