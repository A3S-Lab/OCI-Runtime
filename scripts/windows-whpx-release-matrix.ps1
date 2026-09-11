[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$RootfsArchive,
    [Parameter(Mandatory)]
    [string]$SystemImageManifest,
    [ValidateSet('existing', 'fresh')]
    [string]$HostClass = 'existing',
    [string]$FreshHostAttestation = '',
    [string]$OutputDirectory = '',
    [switch]$SkipBuild,
    [switch]$SkipOperationReopen,
    [switch]$SkipSoak
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'The WHPX release matrix must run on Windows.'
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$rootfsArchive = (Resolve-Path -LiteralPath $RootfsArchive -ErrorAction Stop).Path
$systemImageManifest = (Resolve-Path -LiteralPath $SystemImageManifest -ErrorAction Stop).Path
$cli = Join-Path $repositoryRoot 'target\debug\a3s-oci.exe'
$shim = Join-Path $repositoryRoot 'target\debug\a3s-oci-krun-shim.exe'
$krunDll = Join-Path $repositoryRoot 'target\debug\krun.dll'
$firmwareDll = Join-Path $repositoryRoot 'target\debug\libkrunfw.dll'
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Write-Utf8Text {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [AllowEmptyString()] [Parameter(Mandatory)] [string]$Text
    )
    [IO.File]::WriteAllText($Path, $Text, $script:utf8NoBom)
}

function Get-Sha256 {
    param([Parameter(Mandatory)] [string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-RegularFile {
    param([Parameter(Mandatory)] [string]$Path, [Parameter(Mandatory)] [string]$Label)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or $item.Length -le 0) {
        throw "$Label must be a non-empty regular file: $Path"
    }
    if ($item.PSObject.Properties.Name -contains 'LinkType' -and
        $item.LinkType -eq 'SymbolicLink') {
        throw "$Label must not be a link: $Path"
    }
    return $item
}

function Get-OptionalProperty {
    param(
        [Parameter(Mandatory)] [object]$Object,
        [Parameter(Mandatory)] [string]$Name
    )
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Get-A3sOciProcesses {
    @(
        Get-Process -ErrorAction SilentlyContinue |
            Where-Object { $_.ProcessName -in @('a3s-oci', 'a3s-oci-krun-shim') } |
            Select-Object ProcessName, Id
    )
}

function Assert-NoA3sOciProcesses {
    param([string]$Context)
    $processes = @(Get-A3sOciProcesses)
    if ($processes.Count -gt 0) {
        $description = ($processes | ForEach-Object {
            '{0}:{1}' -f $_.ProcessName, $_.Id
        }) -join ', '
        throw "$Context found active A3S OCI processes: $description"
    }
}

. (Join-Path $PSScriptRoot 'lib\windows-whpx-fresh-host-attestation.ps1')
. (Join-Path $PSScriptRoot 'lib\windows-whpx-release-matrix-promotion.ps1')

Assert-WhpxFreshHostSkipPolicy `
    -HostClass $HostClass `
    -SkipSoak:$SkipSoak `
    -SkipOperationReopen:$SkipOperationReopen

function Invoke-GateScript {
    param(
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$ScriptPath,
        [Parameter(Mandatory)] [string]$GateOutputDirectory,
        [Parameter(Mandatory)] [string]$ExpectedSummarySchema,
        [string]$SummaryRelativePath = 'summary.json',
        [string[]]$ExtraArguments = @()
    )

    if (-not (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
        throw "Missing WHPX gate script: $ScriptPath"
    }
    if (Test-Path -LiteralPath $GateOutputDirectory) {
        throw "Refusing to reuse an existing gate output directory: $GateOutputDirectory"
    }
    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', $ScriptPath,
        '-RootfsArchive', $script:rootfsArchive,
        '-SystemImageManifest', $script:systemImageManifest,
        '-OutputDirectory', $GateOutputDirectory,
        '-SkipBuild'
    ) + $ExtraArguments

    Write-Host ("BEGIN {0}" -f $Name)
    $started = [DateTime]::UtcNow
    $childOutput = & powershell.exe @arguments 2>&1
    $childExitCode = $LASTEXITCODE
    foreach ($line in @($childOutput)) {
        Write-Host $line
    }
    if ($childExitCode -ne 0) {
        throw "$Name failed with exit code $childExitCode"
    }
    $summaryPath = Join-Path $GateOutputDirectory $SummaryRelativePath
    Assert-RegularFile -Path $summaryPath -Label "$Name summary" | Out-Null
    $summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
    $schema = Get-OptionalProperty -Object $summary -Name 'schema_version'
    if ($null -eq $schema) {
        $schema = Get-OptionalProperty -Object $summary -Name 'schema'
    }
    if ($schema -ne $ExpectedSummarySchema) {
        throw "$Name summary schema mismatch: expected $ExpectedSummarySchema, found $schema"
    }
    $status = Get-OptionalProperty -Object $summary -Name 'status'
    $result = Get-OptionalProperty -Object $summary -Name 'result'
    if ($null -ne $status -and $status -ne 'available') {
        throw "$Name summary status is $status, expected available"
    }
    if ($null -ne $result -and $result -ne 'pass') {
        throw "$Name summary result is $result, expected pass"
    }
    Assert-NoA3sOciProcesses -Context "$Name completion"
    $durationMs = [int]([DateTime]::UtcNow - $started).TotalMilliseconds
    Write-Host ("PASS {0} ({1} ms)" -f $Name, $durationMs)
    return [pscustomobject][ordered]@{
        name = $Name
        schema_version = $ExpectedSummarySchema
        status = if ($null -ne $status) { $status } else { $result }
        duration_ms = $durationMs
        summary_path = $summaryPath
        summary_sha256 = (Get-Sha256 -Path $summaryPath)
        output_directory = $GateOutputDirectory
    }
}

Assert-RegularFile -Path $rootfsArchive -Label 'Rootfs archive' | Out-Null
Assert-RegularFile -Path $systemImageManifest -Label 'System-image manifest' | Out-Null
$systemImage = Get-Content -LiteralPath $systemImageManifest -Raw | ConvertFrom-Json
if ($systemImage.schema_version -ne 'a3s.oci.windows-system-image.v1' -or
    $systemImage.architecture -ne 'x86_64' -or
    $systemImage.image.name -ne 'a3s-oci-system.ext4') {
    throw "Unexpected Windows system-image manifest: $systemImageManifest"
}
$manifestDirectory = (Get-Item -LiteralPath $systemImageManifest).DirectoryName
$systemImagePath = Join-Path $manifestDirectory $systemImage.image.name
Assert-RegularFile -Path $systemImagePath -Label 'Windows system image' | Out-Null
$systemImageSha256 = Get-Sha256 -Path $systemImagePath
if ($systemImageSha256 -ne $systemImage.image.sha256 -or
    (Get-Item -LiteralPath $systemImagePath).Length -ne [uint64]$systemImage.image.size) {
    throw "Windows system image does not match its manifest: $systemImagePath"
}
$systemImageManifestSha256 = Get-Sha256 -Path $systemImageManifest
$rootfsSha256 = Get-Sha256 -Path $rootfsArchive
# Always resolve so existing+attestation-path fails closed (mirrors Linux KVM).
$freshHostAttestation = Resolve-WhpxFreshHostAttestation `
    -HostClass $HostClass `
    -AttestationPath $FreshHostAttestation
$hasFreshHostAttestation = $null -ne $freshHostAttestation

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $runId = '{0}-{1}' -f (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'), $PID
    $OutputDirectory = Join-Path $repositoryRoot "target\windows-whpx-release-matrix\$runId"
}
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $outputRoot) {
    throw "Refusing to reuse an existing WHPX release-matrix directory: $outputRoot"
}
New-Item -ItemType Directory -Path (Join-Path $outputRoot 'gates') | Out-Null
if ($hasFreshHostAttestation) {
    $attestationPath = [string](Get-OptionalProperty -Object $freshHostAttestation -Name 'path')
    if ([string]::IsNullOrWhiteSpace($attestationPath)) {
        throw 'Fresh-host attestation is missing a concrete path.'
    }
    Copy-Item -LiteralPath $attestationPath `
        -Destination (Join-Path $outputRoot 'fresh-host-attestation.json') -Force
}

if (-not $SkipBuild) {
    & cargo.exe build --manifest-path (Join-Path $repositoryRoot 'Cargo.toml') `
        -p a3s-oci-cli -p a3s-oci-krun
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to build the Windows WHPX qualification binaries.'
    }
}
Assert-RegularFile -Path $cli -Label 'OCI CLI binary' | Out-Null
Assert-RegularFile -Path $shim -Label 'libkrun shim binary' | Out-Null
Assert-RegularFile -Path $krunDll -Label 'krun.dll' | Out-Null
Assert-RegularFile -Path $firmwareDll -Label 'libkrunfw.dll' | Out-Null
$krunSha256 = Get-Sha256 -Path $krunDll
$firmwareSha256 = Get-Sha256 -Path $firmwareDll
if ($systemImage.runtime.krun_dll.sha256 -ne $krunSha256 -or
    $systemImage.runtime.firmware.sha256 -ne $firmwareSha256) {
    throw 'Windows runtime DLLs do not match the immutable system-image manifest.'
}

Assert-NoA3sOciProcesses -Context 'Release matrix start'
$startedAt = [DateTime]::UtcNow
$gates = New-Object 'System.Collections.Generic.List[object]'

$gates.Add((Invoke-GateScript `
    -Name 'handle-reclamation' `
    -ScriptPath (Join-Path $PSScriptRoot 'windows-whpx-handle-reclamation.ps1') `
    -GateOutputDirectory (Join-Path $outputRoot 'gates\handle-reclamation') `
    -ExpectedSummarySchema 'a3s.oci.windows-whpx-handle-reclamation-run.v1'))

$gates.Add((Invoke-GateScript `
    -Name 'driver-smoke' `
    -ScriptPath (Join-Path $PSScriptRoot 'windows-whpx-driver-smoke.ps1') `
    -GateOutputDirectory (Join-Path $outputRoot 'gates\driver-smoke') `
    -ExpectedSummarySchema 'a3s.oci.whpx-driver-smoke-run.v1'))

$gates.Add((Invoke-GateScript `
    -Name 'recovery-smoke' `
    -ScriptPath (Join-Path $PSScriptRoot 'windows-whpx-recovery-smoke.ps1') `
    -GateOutputDirectory (Join-Path $outputRoot 'gates\recovery-smoke') `
    -ExpectedSummarySchema 'a3s.oci.whpx-recovery-smoke-run.v1'))

$gates.Add((Invoke-GateScript `
    -Name 'transport-fault-cleanup' `
    -ScriptPath (Join-Path $PSScriptRoot 'windows-whpx-transport-fault-cleanup.ps1') `
    -GateOutputDirectory (Join-Path $outputRoot 'gates\transport-fault-cleanup') `
    -ExpectedSummarySchema 'a3s.oci.whpx-transport-fault-cleanup-run.v1'))

if (-not $SkipSoak) {
    $soakExtra = @()
    if ($HostClass -eq 'fresh') {
        $soakExtra = @('-Iterations', "$script:WhpxPromotionSoakIterations")
    }
    $gates.Add((Invoke-GateScript `
        -Name 'soak' `
        -ScriptPath (Join-Path $PSScriptRoot 'windows-whpx-soak.ps1') `
        -GateOutputDirectory (Join-Path $outputRoot 'gates\soak') `
        -ExpectedSummarySchema 'a3s.oci.windows-whpx-soak.v2' `
        -SummaryRelativePath 'evidence\summary.json' `
        -ExtraArguments $soakExtra))
}

if (-not $SkipOperationReopen) {
    $gates.Add((Invoke-GateScript `
        -Name 'operation-reopen' `
        -ScriptPath (Join-Path $PSScriptRoot 'windows-whpx-operation-reopen.ps1') `
        -GateOutputDirectory (Join-Path $outputRoot 'gates\operation-reopen') `
        -ExpectedSummarySchema 'a3s.oci.whpx-operation-reopen-run.v1'))
}

$soakRequestedIterations = 0
$soakCompletedIterations = 0
if (-not $SkipSoak) {
    $soakSummaryPath = Join-Path $outputRoot 'gates\soak\evidence\summary.json'
    Assert-RegularFile -Path $soakSummaryPath -Label 'WHPX soak summary' | Out-Null
    $soakSummary = Get-Content -LiteralPath $soakSummaryPath -Raw | ConvertFrom-Json
    $soakRequestedIterations = [int](Get-OptionalProperty -Object $soakSummary -Name 'requested_iterations')
    $soakCompletedIterations = [int](Get-OptionalProperty -Object $soakSummary -Name 'completed_iterations')
    Assert-WhpxFreshHostSoakProfile `
        -HostClass $HostClass `
        -RequestedIterations $soakRequestedIterations
}

$operationReopenCaseCount = 0
if (-not $SkipOperationReopen) {
    $reopenSummaryPath = Join-Path $outputRoot 'gates\operation-reopen\summary.json'
    Assert-RegularFile -Path $reopenSummaryPath -Label 'WHPX operation-reopen summary' | Out-Null
    $reopenSummary = Get-Content -LiteralPath $reopenSummaryPath -Raw | ConvertFrom-Json
    $operationReopenCaseCount = [int](Get-OptionalProperty -Object $reopenSummary -Name 'case_count')
    Assert-WhpxFreshHostOperationReopenProfile `
        -HostClass $HostClass `
        -CaseCount $operationReopenCaseCount
}

$completedAt = [DateTime]::UtcNow
$promotesReadiness = Get-WhpxPromotesReadiness `
    -HostClass $HostClass `
    -HasFreshHostAttestation $hasFreshHostAttestation `
    -SkipSoak:$SkipSoak `
    -SkipOperationReopen:$SkipOperationReopen `
    -GateCount $gates.Count `
    -SoakRequestedIterations $soakRequestedIterations `
    -SoakCompletedIterations $soakCompletedIterations `
    -OperationReopenCaseCount $operationReopenCaseCount
$summary = [ordered]@{
    schema_version = 'a3s.oci.windows-whpx-release-matrix.v1'
    status = 'available'
    host_class = $HostClass
    promotes_readiness = $promotesReadiness
    fresh_host_attestation = $freshHostAttestation
    started_at_utc = $startedAt.ToString('o')
    completed_at_utc = $completedAt.ToString('o')
    duration_seconds = [Math]::Round(($completedAt - $startedAt).TotalSeconds, 3)
    commit = (& git -C $repositoryRoot rev-parse HEAD).Trim()
    rootfs_archive = $rootfsArchive
    rootfs_archive_sha256 = $rootfsSha256
    system_image_manifest = $systemImageManifest
    system_image_manifest_sha256 = $systemImageManifestSha256
    system_image_sha256 = $systemImageSha256
    cli_sha256 = (Get-Sha256 -Path $cli)
    shim_sha256 = (Get-Sha256 -Path $shim)
    krun_dll_sha256 = $krunSha256
    firmware_dll_sha256 = $firmwareSha256
    included_operation_reopen = (-not $SkipOperationReopen)
    included_soak = (-not $SkipSoak)
    soak_requested_iterations = $soakRequestedIterations
    soak_completed_iterations = $soakCompletedIterations
    operation_reopen_case_count = $operationReopenCaseCount
    gate_count = $gates.Count
    gates = $gates
}
if ($HostClass -eq 'fresh') {
    if (-not $promotesReadiness) {
        throw 'HostClass=fresh completed without promotes_readiness=true; refusing dishonest promotion evidence.'
    }
    if ($summary.gate_count -ne 6 -or -not $summary.included_soak -or -not $summary.included_operation_reopen) {
        throw 'HostClass=fresh requires the full six-gate bound set including soak and operation-reopen.'
    }
    if ($soakRequestedIterations -ne $script:WhpxPromotionSoakIterations -or
        $soakCompletedIterations -ne $script:WhpxPromotionSoakIterations) {
        throw 'HostClass=fresh requires full soak depth (requested_iterations=completed_iterations=25).'
    }
    if ($operationReopenCaseCount -ne $script:WhpxPromotionOperationReopenCases) {
        throw 'HostClass=fresh requires full operation-reopen depth (case_count=180).'
    }
}
Write-Utf8Text -Path (Join-Path $outputRoot 'summary.json') `
    -Text ($summary | ConvertTo-Json -Depth 16)
Assert-NoA3sOciProcesses -Context 'Release matrix completion'

Write-Output ("WHPX release matrix passed: {0} gates (host_class={1})" -f $gates.Count, $HostClass)
Write-Output "Evidence: $outputRoot"
if ($HostClass -ne 'fresh') {
    Write-Output 'host_class=existing does not close the fresh-host promotion gate.'
} else {
    Write-Output 'host_class=fresh retained with digest-bound FreshHostAttestation; promote only from that evidence.'
}
