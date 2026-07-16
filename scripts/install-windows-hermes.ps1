param(
  [string]$Version = "0.71.1",
  [ValidateSet("x64", "arm64", "x86")]
  [string]$Arch = "x64",
  [switch]$Force
)

$ErrorActionPreference = "Stop"

$PackageId = "ReactNative.Hermes.Windows"
$ReviewedVersion = "0.71.1"
$ReviewedPackageSha512 = "c6d2ba6bba442b44ce4f1d5c0e7eb2c9d3fcafe24765464e3a01607c0ccafadb4b028a4cb502e6779c7d0bf3c11d8e591d8a6150cbf9137aee70a2fe62371f74"
$NuGetServiceIndex = "https://api.nuget.org/v3/index.json"
$NuGetFlatContainerBase = "https://api.nuget.org/v3-flatcontainer"

if ($Version -ne $ReviewedVersion) {
  throw "No reviewed NuGet checksum is pinned for $PackageId $Version. Update the coordinate, checksum, and evaluator review together."
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path (Join-Path $scriptDir "..")
$targetRoot = Join-Path $repoRoot "tools\hermes\windows-$Arch"
$includeDir = Join-Path $targetRoot "include"
$libDir = Join-Path $targetRoot "lib"
$binDir = Join-Path $targetRoot "bin"
$profileReceiptPath = Join-Path $binDir "hermes-profile-provenance.json"

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
  if (-not (Test-Path $profileReceiptPath)) { return $false }
  foreach ($dll in $runtimeDlls) {
    if (-not (Test-Path (Join-Path $binDir $dll))) { return $false }
  }
  try {
    $receipt = Get-Content -LiteralPath $profileReceiptPath -Raw | ConvertFrom-Json
    $expectedArchitecture = if ($Arch -eq "x64") { "x86_64" } elseif ($Arch -eq "arm64") { "aarch64" } else { "x86" }
    $binaryDigest = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $binDir "hermes.dll")).Hash.ToLowerInvariant()
    $linkDigest = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $libDir "hermes.lib")).Hash.ToLowerInvariant()
    if ($receipt.schema -ne "ibex/hermes-profile-provenance-receipt/2") { return $false }
    if ($receipt.profileId -ne "windows-nuget") { return $false }
    if ($receipt.targetVariant -ne "windows") { return $false }
    if ($receipt.origin.reviewedProfileIdentity.packageDigest -ne "sha512-$ReviewedPackageSha512") { return $false }
    if ($receipt.origin.packageSignature.serviceIndex -ne $NuGetServiceIndex) { return $false }
    if ($receipt.artifact.binaryDigest -ne "sha256-$binaryDigest") { return $false }
    if ($receipt.artifact.fileName -ne "hermes.dll") { return $false }
    if ($receipt.artifact.targetArchitecture -ne $expectedArchitecture) { return $false }
    if ($receipt.linkArtifact.binaryDigest -ne "sha256-$linkDigest") { return $false }
    if ($receipt.linkArtifact.fileName -ne "hermes.lib") { return $false }
    if ($receipt.linkArtifact.targetArchitecture -ne $expectedArchitecture) { return $false }
  }
  catch {
    return $false
  }
  return $true
}

function Assert-ReviewedNuGetPackage {
  param([string]$PackagePath)

  $observed = (Get-FileHash -Algorithm SHA512 -LiteralPath $PackagePath).Hash.ToLowerInvariant()
  if ($observed -ne $ReviewedPackageSha512) {
    throw "NuGet package checksum mismatch for $PackageId $Version. Reviewed sha512-$ReviewedPackageSha512, observed sha512-$observed."
  }
  if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    throw "dotnet is required to verify the NuGet repository signature for $PackageId $Version."
  }
  & dotnet nuget verify $PackagePath --all --verbosity minimal
  if ($LASTEXITCODE -ne 0) {
    throw "NuGet repository signature verification failed for $PackageId $Version."
  }
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

function Write-HermesProfileReceipt {
  param(
    [string]$PackagePath,
    [string]$PackageSource
  )

  $binaryPath = Join-Path $binDir "hermes.dll"
  $linkPath = Join-Path $libDir "hermes.lib"
  if (-not (Test-Path -LiteralPath $binaryPath)) {
    throw "Cannot bind Windows Hermes provenance: $binaryPath is absent"
  }
  if (-not (Test-Path -LiteralPath $linkPath)) {
    throw "Cannot bind Windows Hermes provenance: $linkPath is absent"
  }
  $targetArchitecture = if ($Arch -eq "x64") { "x86_64" } elseif ($Arch -eq "arm64") { "aarch64" } else { "x86" }
  $binaryDigest = (Get-FileHash -Algorithm SHA256 -LiteralPath $binaryPath).Hash.ToLowerInvariant()
  $linkDigest = (Get-FileHash -Algorithm SHA256 -LiteralPath $linkPath).Hash.ToLowerInvariant()
  $packageDigest = (Get-FileHash -Algorithm SHA512 -LiteralPath $PackagePath).Hash.ToLowerInvariant()
  $receipt = [ordered]@{
    schema = "ibex/hermes-profile-provenance-receipt/2"
    profileId = "windows-nuget"
    targetVariant = "windows"
    artifact = [ordered]@{
      binaryDigest = "sha256-$binaryDigest"
      fileName = "hermes.dll"
      targetArchitecture = $targetArchitecture
    }
    linkArtifact = [ordered]@{
      binaryDigest = "sha256-$linkDigest"
      fileName = "hermes.lib"
      targetArchitecture = $targetArchitecture
    }
    origin = [ordered]@{
      kind = "nuget-package"
      packageCoordinate = "$PackageId`:$Version"
      packageDigest = "sha512-$packageDigest"
      packageRepository = $PackageSource
      packageSignature = [ordered]@{
        kind = "nuget-repository-signature"
        serviceIndex = $NuGetServiceIndex
        verification = "dotnet-nuget-verify-all"
      }
      reviewedProfileIdentity = [ordered]@{
        artifact = $PackageId
        packageDigest = "sha512-$ReviewedPackageSha512"
        repositorySignature = [ordered]@{
          serviceIndex = $NuGetServiceIndex
          type = "repository"
        }
        version = $Version
      }
    }
  }
  $json = $receipt | ConvertTo-Json -Depth 8
  $temporary = "$profileReceiptPath.tmp-$([System.Guid]::NewGuid().ToString('N'))"
  [System.IO.File]::WriteAllText(
    $temporary,
    $json + [Environment]::NewLine,
    (New-Object System.Text.UTF8Encoding($false))
  )
  Move-Item -LiteralPath $temporary -Destination $profileReceiptPath -Force
  Write-Host "Wrote Windows Hermes NuGet coordinate + byte provenance receipt at $profileReceiptPath"
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
  $uri = "$NuGetFlatContainerBase/$($PackageId.ToLowerInvariant())/$Version/$($PackageId.ToLowerInvariant()).$Version.nupkg"
  Write-Host "Downloading $uri"
  Invoke-WebRequest -Uri $uri -OutFile $packagePath
  Assert-ReviewedNuGetPackage $packagePath
  Copy-Item -Path $packagePath -Destination $zipPath -Force
  Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force
  if (-not (Test-Path (Join-Path $extractDir ".signature.p7s"))) {
    throw "The reviewed NuGet package is missing its repository signature."
  }

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
  Write-HermesProfileReceipt $packagePath $NuGetServiceIndex

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
