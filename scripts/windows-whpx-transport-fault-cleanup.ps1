[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$RootfsArchive,
    [Parameter(Mandatory)]
    [string]$SystemImageManifest,
    [string]$OutputDirectory = '',
    [string[]]$Stages = @(
        'host-before-request-write',
        'host-after-request-write',
        'host-before-response-read',
        'host-after-response-read',
        'guest-after-request-read',
        'guest-before-dispatch',
        'guest-after-dispatch',
        'guest-before-response-write',
        'guest-after-response-write',
        'host-before-shutdown',
        'host-after-shutdown'
    ),
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'The WHPX transport-fault cleanup gate must run on Windows.'
}

$expectedRootfsSha256 = '4b4daa9fe2fc696c4919c4412a4c3d3e770d8fb70292a004a2c72f5096175282'
$expectedStages = @(
    'host-before-request-write',
    'host-after-request-write',
    'host-before-response-read',
    'host-after-response-read',
    'guest-after-request-read',
    'guest-before-dispatch',
    'guest-after-dispatch',
    'guest-before-response-write',
    'guest-after-response-write',
    'host-before-shutdown',
    'host-after-shutdown'
)
$guestDisconnectOperations = @(
    'agent-protocol',
    'read-agent-frame-header',
    'read-agent-frame-payload',
    'write-agent-frame-header',
    'write-agent-frame-payload',
    'flush-agent-frame'
)

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$rootfsArchive = (Resolve-Path -LiteralPath $RootfsArchive -ErrorAction Stop).Path
$systemImageManifest = (Resolve-Path -LiteralPath $SystemImageManifest -ErrorAction Stop).Path
$fixtureConfig = Join-Path $repositoryRoot 'fixtures\utility-vm\config.windows.json'
$cli = Join-Path $repositoryRoot 'target\debug\a3s-oci.exe'
$shim = Join-Path $repositoryRoot 'target\debug\a3s-oci-krun-shim.exe'
$krunDll = Join-Path $repositoryRoot 'target\debug\krun.dll'
$firmwareDll = Join-Path $repositoryRoot 'target\debug\libkrunfw.dll'
$tar = (Get-Command tar.exe -ErrorAction Stop).Source
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Write-Utf8Text {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [AllowEmptyString()] [Parameter(Mandatory)] [string]$Text
    )
    [IO.File]::WriteAllText($Path, $Text, $script:utf8NoBom)
}

function ConvertTo-NativeArgument {
    param([AllowEmptyString()] [Parameter(Mandatory)] [string]$Argument)
    if ($Argument.Contains('"')) {
        throw "Native argument contains an unsupported quote: $Argument"
    }
    if ($Argument.Length -eq 0 -or $Argument -match '\s') {
        return '"' + $Argument + '"'
    }
    return $Argument
}

function Invoke-CapturedProcess {
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(Mandatory)] [string[]]$Arguments,
        [Parameter(Mandatory)] [string]$StdoutPath,
        [Parameter(Mandatory)] [string]$StderrPath,
        [int]$TimeoutSeconds = 180
    )
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = (
        $Arguments | ForEach-Object { ConvertTo-NativeArgument -Argument $_ }
    ) -join ' '
    $startInfo.WorkingDirectory = $script:repositoryRoot
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "Failed to start native process: $FilePath"
    }
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while (-not $process.WaitForExit(250)) {
        if ($timer.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
            [void]$process.WaitForExit(5000)
            throw "Timed out after $TimeoutSeconds seconds: $FilePath"
        }
    }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    Write-Utf8Text -Path $StdoutPath -Text $stdout
    Write-Utf8Text -Path $StderrPath -Text $stderr
    [pscustomobject]@{
        ExitCode = $process.ExitCode
        Stdout = $stdout
        Stderr = $stderr
        DurationMs = [int]$timer.Elapsed.TotalMilliseconds
    }
    $process.Dispose()
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

function Get-Sha256 {
    param([Parameter(Mandatory)] [string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function New-TransportFixture {
    param(
        [Parameter(Mandatory)] [string]$FixtureRoot,
        [Parameter(Mandatory)] [string]$CgroupName
    )
    $bootstrap = Join-Path $FixtureRoot 'bootstrap'
    $share = Join-Path $FixtureRoot 'runtime-share'
    $bundle = Join-Path $share 'bundle'
    $containerRootfs = Join-Path $bundle 'rootfs'
    New-Item -ItemType Directory -Path `
        (Join-Path $bootstrap 'dev'),
        (Join-Path $bootstrap 'newroot'),
        (Join-Path $bootstrap 'proc'),
        (Join-Path $bootstrap 'sys'),
        (Join-Path $share 'run'),
        $containerRootfs | Out-Null
    & $script:tar -xf $script:rootfsArchive -C $containerRootfs
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to extract the immutable container rootfs into $FixtureRoot"
    }
    $config = Get-Content -LiteralPath $script:fixtureConfig -Raw | ConvertFrom-Json
    $config.linux.cgroupsPath = $CgroupName
    Write-Utf8Text -Path (Join-Path $bundle 'config.json') `
        -Text ($config | ConvertTo-Json -Depth 32)
    [pscustomobject]@{
        Bootstrap = $bootstrap
        RuntimeShare = $share
        Bundle = $bundle
    }
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

function Assert-WindowsShimHandleReclamation {
    param(
        [Parameter(Mandatory)] [string]$Label,
        [Parameter(Mandatory)] [object]$Bridge
    )
    $shim = Get-OptionalProperty -Object $Bridge -Name 'shim_report'
    if ($null -eq $shim -or
        $shim.platform -ne 'windows' -or
        $shim.windows_handle_inventory_restored -ne $true -or
        [uint64]$shim.windows_handles_before_vm -le 0 -or
        [uint64]$shim.windows_handles_after_vm -ne
            [uint64]$shim.windows_handles_before_vm) {
        throw "$Label did not prove in-process WHPX/libkrun handle reclamation"
    }
}

function Assert-TransportFaultReport {
    param(
        [Parameter(Mandatory)] [string]$Label,
        [Parameter(Mandatory)] [string]$Stage,
        [Parameter(Mandatory)] [object]$Result,
        [Parameter(Mandatory)] [string]$SystemImageManifestSha256,
        [Parameter(Mandatory)] [string]$SystemImageSha256
    )

    if ($Result.ExitCode -ne 0 -or $null -eq $Result.Report) {
        throw "$Label did not complete successfully; see report output"
    }
    $report = $Result.Report
    $reason = Get-OptionalProperty -Object $report -Name 'reason'
    $guestEvidenceOperationId = Get-OptionalProperty -Object $report `
        -Name 'guest_evidence_operation_id'
    $qualificationOperationId = Get-OptionalProperty -Object $report `
        -Name 'qualification_operation_id'
    if ($report.schema_version -ne 'a3s.oci.oci-vm-transport-fault-cleanup.v3' -or
        $report.platform -ne 'windows' -or
        $report.status -ne 'available' -or
        $report.bundle_loaded -ne $true -or
        $report.requested_operation -ne 'create' -or
        $null -eq $qualificationOperationId -or
        -not ($qualificationOperationId -like 'transport-fault-*') -or
        $report.requested_stage -ne $Stage -or
        $report.negotiated_protocol -ne 10 -or
        $report.fault_crossings -ne 1 -or
        $report.observed_error_code -ne 'unavailable' -or
        $report.observed_error_retryable -ne $true -or
        $report.normal_delete_attempted -ne $false -or
        $report.marker_absent_after_cleanup -ne $true -or
        $report.guest_runtime_clean -ne $true -or
        $null -ne $reason -or
        $report.bridge.status -ne 'available' -or
        $report.bridge.protocol_negotiated -ne $true -or
        $report.bridge.selected_protocol -ne 10 -or
        $report.bridge.shim_report_verified -ne $true -or
        $report.bridge.shim_exit_code -ne 0) {
        throw "$Label emitted incomplete transport-fault evidence"
    }

    $expectedPoint = if ($Stage.EndsWith('-shutdown')) {
        "agent-v10.$Stage"
    } else {
        "agent-v10.create-$Stage"
    }
    if ($report.injected_point -ne $expectedPoint) {
        throw "$Label injected_point mismatch: expected $expectedPoint, found $($report.injected_point)"
    }

    if ($Stage.EndsWith('-shutdown')) {
        if ($report.observed_error_operation -ne 'oci-vm-transport-qualification-fault' -or
            $report.primary_response_received -ne $true -or
            $report.disconnect_probe_attempted -ne $false -or
            $report.guest_evidence_verified -ne $false -or
            $null -ne $guestEvidenceOperationId) {
            throw "$Label did not retain exact Host shutdown interruption evidence"
        }
    } elseif ($Stage.StartsWith('host-')) {
        if ($report.observed_error_operation -ne 'oci-vm-transport-qualification-fault' -or
            $report.primary_response_received -ne $false -or
            $report.disconnect_probe_attempted -ne $false -or
            $report.guest_evidence_verified -ne $false -or
            $null -ne $guestEvidenceOperationId) {
            throw "$Label did not retain exact Host request/response interruption evidence"
        }
    } else {
        if ($script:guestDisconnectOperations -notcontains $report.observed_error_operation -or
            $report.guest_evidence_verified -ne $true -or
            $guestEvidenceOperationId -ne $qualificationOperationId) {
            throw "$Label did not retain exact Guest disconnect evidence"
        }
        $expectPrimary = $Stage -eq 'guest-after-response-write'
        if ($report.primary_response_received -ne $expectPrimary -or
            $report.disconnect_probe_attempted -ne $expectPrimary) {
            throw "$Label mismatched Guest response/disconnect probe flags for $Stage"
        }
    }

    Assert-WindowsShimHandleReclamation -Label $Label -Bridge $report.bridge
    $shim = Get-OptionalProperty -Object $report.bridge -Name 'shim_report'
    $bootAssets = Get-OptionalProperty -Object $shim -Name 'windows_boot_assets'
    if ($null -eq $bootAssets -or
        $bootAssets.manifest_sha256 -ne $SystemImageManifestSha256 -or
        $bootAssets.system_image_sha256 -ne $SystemImageSha256) {
        throw "$Label lacked exact WHPX immutable boot-asset evidence"
    }
}

Assert-RegularFile -Path $rootfsArchive -Label 'Rootfs archive' | Out-Null
$rootfsSha256 = Get-Sha256 -Path $rootfsArchive
if ($rootfsSha256 -ne $expectedRootfsSha256) {
    throw "Rootfs SHA-256 mismatch: expected $expectedRootfsSha256, found $rootfsSha256"
}
Assert-RegularFile -Path $systemImageManifest -Label 'System-image manifest' | Out-Null
Assert-RegularFile -Path $fixtureConfig -Label 'Windows OCI fixture' | Out-Null
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

foreach ($stage in $Stages) {
    if ($expectedStages -notcontains $stage) {
        throw "Unsupported fault stage: $stage"
    }
}
if (@($Stages).Count -ne $expectedStages.Count) {
    throw "Transport-fault gate requires all $($expectedStages.Count) stages; got $(@($Stages).Count)"
}
foreach ($expected in $expectedStages) {
    if ($Stages -notcontains $expected) {
        throw "Transport-fault gate is missing required stage: $expected"
    }
}

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $runId = '{0}-{1}' -f (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'), $PID
    $OutputDirectory = Join-Path $repositoryRoot "target\windows-whpx-transport-fault-cleanup\$runId"
}
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $outputRoot) {
    throw "Refusing to reuse an existing WHPX transport-fault directory: $outputRoot"
}
New-Item -ItemType Directory -Path (Join-Path $outputRoot 'cases') | Out-Null

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

Assert-NoA3sOciProcesses -Context 'Qualification start'
$startedAt = [DateTime]::UtcNow
$results = @()
$caseIndex = 0
foreach ($stage in $Stages) {
    $caseIndex++
    $caseName = '{0:D2}-{1}' -f $caseIndex, $stage
    $caseRoot = Join-Path (Join-Path $outputRoot 'cases') $caseName
    $fixtureRoot = Join-Path $caseRoot 'fixture'
    $consolePath = Join-Path $caseRoot 'console.log'
    New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
    $fixture = New-TransportFixture `
        -FixtureRoot $fixtureRoot `
        -CgroupName "a3s-oci-whpx-transport-$caseIndex"
    $stdoutPath = Join-Path $caseRoot 'report.json'
    $stderrPath = Join-Path $caseRoot 'stderr.log'
    $metadataPath = Join-Path $caseRoot 'case.json'
    $arguments = @(
        'oci-vm-transport-fault-cleanup',
        '--shim', $shim,
        '--vm-rootfs', $fixture.Bootstrap,
        '--system-image-manifest', $systemImageManifest,
        '--runtime-share', $fixture.RuntimeShare,
        '--bundle', $fixture.Bundle,
        '--console', $consolePath,
        '--fault-at', $stage
    )
    Write-Utf8Text -Path $metadataPath -Text (([ordered]@{
        stage = $stage
        rootfs_archive_sha256 = $rootfsSha256
        system_image_manifest_sha256 = $systemImageManifestSha256
        system_image_sha256 = $systemImageSha256
        cli_sha256 = (Get-Sha256 -Path $cli)
        shim_sha256 = (Get-Sha256 -Path $shim)
        krun_sha256 = (Get-Sha256 -Path $krunDll)
        firmware_sha256 = (Get-Sha256 -Path $firmwareDll)
    } | ConvertTo-Json -Depth 8))
    $completed = Invoke-CapturedProcess `
        -FilePath $cli `
        -Arguments $arguments `
        -StdoutPath $stdoutPath `
        -StderrPath $stderrPath
    $report = $null
    try {
        $report = $completed.Stdout | ConvertFrom-Json
    }
    catch {
        throw "$caseName emitted invalid JSON: $($_.Exception.Message)"
    }
    Assert-TransportFaultReport `
        -Label $caseName `
        -Stage $stage `
        -Result ([pscustomobject]@{
            ExitCode = $completed.ExitCode
            Report = $report
        }) `
        -SystemImageManifestSha256 $systemImageManifestSha256 `
        -SystemImageSha256 $systemImageSha256
    $results += [pscustomobject][ordered]@{
        stage = $stage
        status = $report.status
        exit_code = $completed.ExitCode
        duration_ms = $completed.DurationMs
        injected_point = $report.injected_point
        report = $stdoutPath
    }
    Assert-NoA3sOciProcesses -Context "$caseName completion"
    Write-Output ("PASS {0} ({1} ms)" -f $caseName, $completed.DurationMs)
}

$summary = [ordered]@{
    schema_version = 'a3s.oci.whpx-transport-fault-cleanup-run.v1'
    status = 'available'
    started_at_utc = $startedAt.ToString('o')
    completed_at_utc = [DateTime]::UtcNow.ToString('o')
    commit = (& git -C $repositoryRoot rev-parse HEAD).Trim()
    rootfs_archive = $rootfsArchive
    rootfs_archive_sha256 = $rootfsSha256
    system_image_manifest = $systemImageManifest
    system_image_manifest_sha256 = $systemImageManifestSha256
    system_image_sha256 = $systemImageSha256
    stages = $Stages
    expected_case_count = $expectedStages.Count
    case_count = $results.Count
    cases = $results
}
if ($results.Count -ne $expectedStages.Count) {
    throw ("Transport-fault gate expected {0} cases; got {1}" -f `
        $expectedStages.Count, $results.Count)
}
Write-Utf8Text -Path (Join-Path $outputRoot 'summary.json') `
    -Text ($summary | ConvertTo-Json -Depth 16)
Assert-NoA3sOciProcesses -Context 'Qualification completion'
Write-Output "WHPX transport-fault cleanup qualification passed: $($results.Count) cases"
Write-Output "Evidence: $outputRoot"
