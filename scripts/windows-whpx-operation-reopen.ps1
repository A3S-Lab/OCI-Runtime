[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$RootfsArchive,
    [Parameter(Mandatory)]
    [string]$SystemImageManifest,
    [string]$OutputDirectory = '',
    [string[]]$Operations = @(
        'Create', 'State', 'Start', 'Kill', 'Delete', 'Wait', 'Exec',
        'SignalProcess', 'WaitProcess', 'Pause', 'Resume', 'Processes',
        'Update', 'Stats', 'ReadOutput', 'WriteStdin', 'CloseStdin',
        'Resize', 'File', 'Filesystem'
    ),
    [string[]]$Stages = @(
        'host-before-request-write',
        'host-after-request-write',
        'host-before-response-read',
        'host-after-response-read',
        'guest-after-request-read',
        'guest-before-dispatch',
        'guest-after-dispatch',
        'guest-before-response-write',
        'guest-after-response-write'
    ),
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'The WHPX operation/reopen qualification must run on Windows.'
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
    'guest-after-response-write'
)
$operationCliNames = @{
    Create = 'create'
    State = 'state'
    Start = 'start'
    Kill = 'kill'
    Delete = 'delete'
    Wait = 'wait'
    Exec = 'exec'
    SignalProcess = 'signal-process'
    WaitProcess = 'wait-process'
    Pause = 'pause'
    Resume = 'resume'
    Processes = 'processes'
    Update = 'update'
    Stats = 'stats'
    ReadOutput = 'read-output'
    WriteStdin = 'write-stdin'
    CloseStdin = 'close-stdin'
    Resize = 'resize'
    File = 'file'
    Filesystem = 'filesystem'
}
$operationSchemas = @{
    Create = 'a3s.oci.oci-vm-reopen-replacement.v3'
    State = 'a3s.oci.oci-vm-operation-reopen-replacement.v1'
    Start = 'a3s.oci.oci-vm-operation-reopen-replacement.v2'
    Kill = 'a3s.oci.oci-vm-operation-reopen-replacement.v3'
    Delete = 'a3s.oci.oci-vm-operation-reopen-replacement.v4'
    Wait = 'a3s.oci.oci-vm-operation-reopen-replacement.v5'
    Exec = 'a3s.oci.oci-vm-operation-reopen-replacement.v6'
    SignalProcess = 'a3s.oci.oci-vm-operation-reopen-replacement.v7'
    WaitProcess = 'a3s.oci.oci-vm-operation-reopen-replacement.v8'
    Pause = 'a3s.oci.oci-vm-operation-reopen-replacement.v9'
    Resume = 'a3s.oci.oci-vm-operation-reopen-replacement.v10'
    Processes = 'a3s.oci.oci-vm-operation-reopen-replacement.v11'
    Update = 'a3s.oci.oci-vm-operation-reopen-replacement.v12'
    Stats = 'a3s.oci.oci-vm-operation-reopen-replacement.v13'
    ReadOutput = 'a3s.oci.oci-vm-operation-reopen-replacement.v14'
    WriteStdin = 'a3s.oci.oci-vm-operation-reopen-replacement.v15'
    CloseStdin = 'a3s.oci.oci-vm-operation-reopen-replacement.v16'
    Resize = 'a3s.oci.oci-vm-operation-reopen-replacement.v17'
    File = 'a3s.oci.oci-vm-operation-reopen-replacement.v18'
    Filesystem = 'a3s.oci.oci-vm-operation-reopen-replacement.v19'
}

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

function New-OperationFixture {
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

foreach ($operation in $Operations) {
    if (-not $operationCliNames.ContainsKey($operation)) {
        throw "Unsupported operation name: $operation"
    }
}
foreach ($stage in $Stages) {
    if ($expectedStages -notcontains $stage) {
        throw "Unsupported fault stage: $stage"
    }
}

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $runId = '{0}-{1}' -f (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'), $PID
    $OutputDirectory = Join-Path $repositoryRoot "target\windows-whpx-operation-reopen\$runId"
}
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $outputRoot) {
    throw "Refusing to reuse an existing WHPX operation qualification directory: $outputRoot"
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
foreach ($operation in $Operations) {
    foreach ($stage in $Stages) {
        $caseIndex++
        $caseName = '{0:D2}-{1}-{2}' -f $caseIndex, $operation.ToLowerInvariant(), $stage
        $caseRoot = Join-Path (Join-Path $outputRoot 'cases') $caseName
        $fixtureRoot = Join-Path $caseRoot 'fixture'
        $consoleDirectory = Join-Path $caseRoot 'console'
        New-Item -ItemType Directory -Path $fixtureRoot, $consoleDirectory | Out-Null
        $fixture = New-OperationFixture `
            -FixtureRoot $fixtureRoot `
            -CgroupName "a3s-oci-whpx-reopen-$caseIndex"
        $stdoutPath = Join-Path $caseRoot 'report.json'
        $stderrPath = Join-Path $caseRoot 'stderr.log'
        $metadataPath = Join-Path $caseRoot 'case.json'
        $arguments = @(
            'oci-vm-reopen-replacement',
            '--operation', $operationCliNames[$operation],
            '--shim', $shim,
            '--vm-rootfs', $fixture.Bootstrap,
            '--system-image-manifest', $systemImageManifest,
            '--bundle', $fixture.Bundle,
            '--console-dir', $consoleDirectory,
            '--fault-at', $stage
        )
        Write-Utf8Text -Path $metadataPath -Text (([ordered]@{
            operation = $operationCliNames[$operation]
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
        $expectedSchema = $operationSchemas[$operation]
        if ($completed.ExitCode -ne 0 -or $report.status -ne 'available') {
            throw "$caseName failed with exit code $($completed.ExitCode); see $stdoutPath"
        }
        if ($report.schema_version -ne $expectedSchema -or
            $report.platform -ne 'windows' -or
            $report.requested_operation -ne $operationCliNames[$operation] -or
            $report.requested_stage -ne $stage -or
            $report.fault_crossings -ne 1 -or
            -not $report.owners_distinct -or
            -not $report.state_root_removed -or
            -not $report.first_vm -or
            -not $report.replacement_vm -or
            $report.first_vm.status -ne 'available' -or
            $report.replacement_vm.status -ne 'available') {
            throw "$caseName emitted an incomplete qualification report: $stdoutPath"
        }
        foreach ($owner in @($report.first_vm, $report.replacement_vm)) {
            if (-not $owner.shim_report.windows_handle_inventory_restored -or
                $owner.shim_report.platform -ne 'windows' -or
                $owner.shim_report.windows_boot_assets.manifest_sha256 -ne $systemImageManifestSha256 -or
                $owner.shim_report.windows_boot_assets.system_image_sha256 -ne $systemImageSha256) {
                throw "$caseName lacked exact WHPX owner asset/handle evidence: $stdoutPath"
            }
        }
        $results += [pscustomobject][ordered]@{
            operation = $operationCliNames[$operation]
            stage = $stage
            status = $report.status
            exit_code = $completed.ExitCode
            duration_ms = $completed.DurationMs
            report = $stdoutPath
        }
        Assert-NoA3sOciProcesses -Context "$caseName completion"
        Write-Output ("PASS {0} ({1} ms)" -f $caseName, $completed.DurationMs)
    }
}

$summary = [ordered]@{
    schema_version = 'a3s.oci.whpx-operation-reopen-run.v1'
    status = 'available'
    started_at_utc = $startedAt.ToString('o')
    completed_at_utc = [DateTime]::UtcNow.ToString('o')
    commit = (& git -C $repositoryRoot rev-parse HEAD).Trim()
    rootfs_archive = $rootfsArchive
    rootfs_archive_sha256 = $rootfsSha256
    system_image_manifest = $systemImageManifest
    system_image_manifest_sha256 = $systemImageManifestSha256
    system_image_sha256 = $systemImageSha256
    operations = @($Operations | ForEach-Object { $operationCliNames[$_] })
    stages = $Stages
    case_count = $results.Count
    cases = $results
}
Write-Utf8Text -Path (Join-Path $outputRoot 'summary.json') `
    -Text ($summary | ConvertTo-Json -Depth 16)
Assert-NoA3sOciProcesses -Context 'Qualification completion'
Write-Output "WHPX operation/reopen qualification passed: $($results.Count) cases"
Write-Output "Evidence: $outputRoot"
