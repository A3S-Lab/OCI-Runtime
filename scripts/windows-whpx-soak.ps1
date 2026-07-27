[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$RootfsArchive,
    [ValidateRange(0, 1000000)]
    [int]$Iterations = 25,
    [ValidateRange(0, 31536000)]
    [int]$DurationSeconds = 0,
    [ValidateRange(1, 1000)]
    [int]$WorkloadIterations = 1,
    [ValidateSet(
        'network-isolated',
        'network-inherited',
        'storage-matrix',
        'init-script',
        'init-script-failure'
    )]
    [string[]]$WorkloadCases = @(
        'network-isolated',
        'network-inherited',
        'storage-matrix',
        'init-script',
        'init-script-failure'
    ),
    [ValidateRange(0, 1000)]
    [int]$ParallelWaves = 3,
    [ValidateRange(1, 16)]
    [int]$Parallelism = 2,
    [ValidateRange(0, 1000)]
    [int]$MultiContainerIterations = 3,
    [ValidateRange(0, 1000)]
    [int]$LifecycleFaultIterations = 1,
    [int[]]$OwnerKillDelayMilliseconds = @(0, 250, 1000, 2500),
    [ValidateRange(1, 3600)]
    [int]$CommandTimeoutSeconds = 120,
    [ValidateRange(1, 16384)]
    [int]$MaxHostProcessWorkingSetMiB = 512,
    [ValidateRange(1, 1024)]
    [int]$MaxSerialLogGrowthMiB = 16,
    [string]$OutputDirectory = '',
    [switch]$SkipBuild,
    [switch]$SkipParallel,
    [switch]$SkipFaultInjection,
    [switch]$SkipNegativeCases,
    [switch]$SkipWorkloadCases
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'The Windows WHPX soak runner must run on Windows.'
}
if ($Iterations -eq 0 -and $DurationSeconds -eq 0) {
    throw 'Specify a positive iteration count, duration, or both.'
}
foreach ($delay in $OwnerKillDelayMilliseconds) {
    if ($delay -lt 0 -or $delay -gt 60000) {
        throw "Owner-kill delays must be between 0 and 60000 milliseconds: $delay"
    }
}

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$fixtureConfig = Join-Path $repositoryRoot 'fixtures\utility-vm\config.windows.json'
$fixtureAssetDirectory = Join-Path $PSScriptRoot 'fixtures\windows-soak'
$cli = Join-Path $repositoryRoot 'target\debug\a3s-oci.exe'
$shim = Join-Path $repositoryRoot 'target\debug\a3s-oci-krun-shim.exe'
$krunDll = Join-Path $repositoryRoot 'target\debug\krun.dll'
$agent = Join-Path $repositoryRoot (
    'target\x86_64-unknown-linux-musl\release\a3s-oci-agent'
)
$rootfsArchive = (Resolve-Path -LiteralPath $RootfsArchive -ErrorAction Stop).Path
$tar = (Get-Command tar.exe -ErrorAction Stop).Source
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

$archiveItem = Get-Item -LiteralPath $rootfsArchive -Force
if ($archiveItem.PSIsContainer -or $archiveItem.Length -le 0) {
    throw "Rootfs archive must be a non-empty regular file: $rootfsArchive"
}
if ($archiveItem.PSObject.Properties.Name -contains 'LinkType' -and $archiveItem.LinkType) {
    throw "Rootfs archive must not be a link: $rootfsArchive"
}
if (-not (Test-Path -LiteralPath $fixtureConfig -PathType Leaf)) {
    throw "Soak fixture configuration is missing: $fixtureConfig"
}

$runId = '{0}-{1}' -f (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'), $PID
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repositoryRoot "target\windows-whpx-soak\$runId"
}
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $outputRoot) {
    throw "Refusing to reuse an existing soak output directory: $outputRoot"
}
$evidenceDirectory = Join-Path $outputRoot 'evidence'
$fixturesDirectory = Join-Path $outputRoot 'fixtures'
New-Item -ItemType Directory -Path $evidenceDirectory, $fixturesDirectory | Out-Null

$activeProcesses = @{}
$samples = @()
$capabilityResults = @()
$startInventory = @()
$finalInventory = @()
$verification = 'running'
$verificationFailures = @()
$completedIterations = 0
$completedParallelRuns = 0
$completedMultiContainerRuns = 0
$completedLifecycleFaults = 0
$completedFaults = 0
$completedNegatives = 0
$completedWorkloadCases = 0
$result = 'running'
$failure = $null
$commit = $null
$worktreeStatus = @()
$rootfsArchiveSha256 = $null
$agentSha256 = $null
$krunDllSha256 = $null
$startedAt = [DateTime]::UtcNow
$soakStartedAt = $null
$serialInitialLogBytes = 0
$serialFinalLogBytes = 0

function Write-Utf8Text {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [AllowEmptyString()]
        [Parameter(Mandatory)]
        [string]$Text
    )

    [IO.File]::WriteAllText($Path, $Text, $script:utf8NoBom)
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [object]$Value
    )

    $json = ConvertTo-Json -InputObject $Value -Depth 20
    if ($null -eq $json) {
        $json = 'null'
    }
    Write-Utf8Text -Path $Path -Text $json
}

function Get-RecordValue {
    param(
        [Parameter(Mandatory)]
        [object]$Record,
        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($Record -is [Collections.IDictionary]) {
        if ($Record.Contains($Name)) {
            return $Record[$Name]
        }
        return $null
    }
    $property = $Record.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    $property.Value
}

function ConvertTo-TsvCell {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return ''
    }
    if ($Value -is [bool]) {
        return $Value.ToString().ToLowerInvariant()
    }
    if ($Value -is [Collections.IEnumerable] -and
        $Value -isnot [string]) {
        $Value = @($Value) -join ','
    }
    ([string]$Value).Replace("`t", ' ').Replace("`r", ' ').Replace("`n", ' ')
}

function Write-RecordsTsv {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string[]]$Columns,
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Rows
    )

    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add(($Columns -join "`t"))
    foreach ($row in $Rows) {
        $cells = @(
            foreach ($column in $Columns) {
                ConvertTo-TsvCell -Value (
                    Get-RecordValue -Record $row -Name $column
                )
            }
        )
        $lines.Add(($cells -join "`t"))
    }
    Write-Utf8Text -Path $Path -Text (($lines -join "`n") + "`n")
}

function Get-SampleMaximum {
    param([Parameter(Mandatory)][string]$Name)

    [int64]$maximum = 0
    foreach ($sample in $script:samples) {
        $value = Get-RecordValue -Record $sample -Name $Name
        if ($null -ne $value) {
            $maximum = [Math]::Max($maximum, [int64]$value)
        }
    }
    $maximum
}

function Write-EvidenceTables {
    $operationColumns = @(
        'sequence',
        'kind',
        'variant',
        'iteration',
        'workload_iteration',
        'wave',
        'lane',
        'fault',
        'delay_ms',
        'result',
        'exit_code',
        'duration_ms',
        'peak_working_set_bytes',
        'shim_exit_ms',
        'expected_code',
        'expected_field',
        'rejection_layer',
        'evidence',
        'evidence_sha256',
        'reason',
        'console'
    )
    $operationRows = @()
    $sequence = 0
    foreach ($sample in $script:samples) {
        $sequence++
        $row = [ordered]@{ sequence = $sequence }
        foreach ($column in $operationColumns | Where-Object { $_ -ne 'sequence' }) {
            $row[$column] = Get-RecordValue -Record $sample -Name $column
        }
        $operationRows += $row
    }
    Write-RecordsTsv `
        -Path (Join-Path $script:evidenceDirectory 'operations.tsv') `
        -Columns $operationColumns -Rows $operationRows

    $resourceColumns = @(
        'sequence',
        'kind',
        'variant',
        'iteration',
        'workload_iteration',
        'wave',
        'lane',
        'duration_ms',
        'peak_working_set_bytes',
        'root_log_bytes',
        'shim_exit_ms'
    )
    $resourceRows = @()
    $sequence = 0
    foreach ($sample in $script:samples) {
        $sequence++
        $row = [ordered]@{ sequence = $sequence }
        foreach ($column in $resourceColumns | Where-Object { $_ -ne 'sequence' }) {
            $row[$column] = Get-RecordValue -Record $sample -Name $column
        }
        $resourceRows += $row
    }
    Write-RecordsTsv `
        -Path (Join-Path $script:evidenceDirectory 'resource-samples.tsv') `
        -Columns $resourceColumns -Rows $resourceRows

    Write-RecordsTsv `
        -Path (Join-Path $script:evidenceDirectory 'capability-results.tsv') `
        -Columns @(
            'capability',
            'result',
            'status',
            'exit_code',
            'duration_ms'
        ) `
        -Rows @($script:capabilityResults)
}

function ConvertTo-NativeArgument {
    param(
        [AllowEmptyString()]
        [Parameter(Mandatory)]
        [string]$Argument
    )

    if ($Argument.Contains('"')) {
        throw "Native argument contains an unsupported quote: $Argument"
    }
    if ($Argument.Length -eq 0 -or $Argument -match '\s') {
        return '"' + $Argument + '"'
    }
    $Argument
}

function Start-CapturedProcess {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        [Parameter(Mandatory)]
        [string[]]$Arguments
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
    $peakWorkingSet = [int64]0
    try {
        $process.Refresh()
        $peakWorkingSet = [Math]::Max(
            [int64]$process.WorkingSet64,
            [int64]$process.PeakWorkingSet64
        )
    }
    catch {
        # The periodic sampler in Complete-CapturedProcess will retry.
    }
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $script:activeProcesses[$process.Id] = $process
    [pscustomobject]@{
        Process = $process
        Stdout = $stdout
        Stderr = $stderr
        Timer = $timer
        PeakWorkingSetBytes = $peakWorkingSet
        FilePath = $FilePath
        Arguments = $Arguments
    }
}

function Complete-CapturedProcess {
    param(
        [Parameter(Mandatory)]
        [object]$Running,
        [int]$TimeoutSeconds = $script:CommandTimeoutSeconds
    )

    $timeoutMilliseconds = [Math]::Min(
        [int]::MaxValue,
        [int64]$TimeoutSeconds * 1000
    )
    $waitTimer = [Diagnostics.Stopwatch]::StartNew()
    $peakWorkingSet = [int64]$Running.PeakWorkingSetBytes
    $timedOut = $false
    while (-not $Running.Process.HasExited) {
        try {
            $Running.Process.Refresh()
            $peakWorkingSet = [Math]::Max(
                $peakWorkingSet,
                [Math]::Max(
                    [int64]$Running.Process.WorkingSet64,
                    [int64]$Running.Process.PeakWorkingSet64
                )
            )
        }
        catch {
            # A process can exit between HasExited and Refresh.
        }
        $remainingMilliseconds = (
            [int64]$timeoutMilliseconds - $waitTimer.ElapsedMilliseconds
        )
        if ($remainingMilliseconds -le 0) {
            $timedOut = $true
            break
        }
        [void]$Running.Process.WaitForExit(
            [int][Math]::Min(100, $remainingMilliseconds)
        )
    }
    $waitTimer.Stop()
    if ($timedOut) {
        $processId = $Running.Process.Id
        try {
            $Running.Process.Kill()
            $Running.Process.WaitForExit()
        }
        finally {
            [void]$script:activeProcesses.Remove($processId)
        }
        throw "Native process timed out after $TimeoutSeconds seconds: $($Running.FilePath)"
    }
    $Running.Process.WaitForExit()
    $Running.Timer.Stop()
    $processId = $Running.Process.Id
    $exitCode = $Running.Process.ExitCode
    if ($peakWorkingSet -le 0) {
        $peakWorkingSet = $null
    }
    $stdout = $Running.Stdout.Result
    $stderr = $Running.Stderr.Result
    [void]$script:activeProcesses.Remove($processId)
    $Running.Process.Dispose()
    [pscustomobject]@{
        ProcessId = $processId
        ExitCode = $exitCode
        DurationMilliseconds = $Running.Timer.ElapsedMilliseconds
        PeakWorkingSetBytes = $peakWorkingSet
        Stdout = $stdout
        Stderr = $stderr
    }
}

function Save-ProcessEvidence {
    param(
        [Parameter(Mandatory)]
        [string]$Label,
        [Parameter(Mandatory)]
        [object]$Completed
    )

    Write-Utf8Text -Path (Join-Path $script:evidenceDirectory "$Label.stdout.json") `
        -Text $Completed.Stdout
    Write-Utf8Text -Path (Join-Path $script:evidenceDirectory "$Label.stderr.log") `
        -Text $Completed.Stderr
}

function Invoke-LoggedNative {
    param(
        [Parameter(Mandatory)]
        [string]$Label,
        [Parameter(Mandatory)]
        [string]$FilePath,
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    Write-Host "+ $FilePath $($Arguments -join ' ')"
    $running = Start-CapturedProcess -FilePath $FilePath -Arguments $Arguments
    $completed = Complete-CapturedProcess -Running $running -TimeoutSeconds 600
    Save-ProcessEvidence -Label $Label -Completed $completed
    if ($completed.ExitCode -ne 0) {
        throw "$Label failed with exit code $($completed.ExitCode)"
    }
}

function Copy-WorkloadAsset {
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [string]$Destination
    )

    $source = Join-Path $script:fixtureAssetDirectory $Name
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Windows soak workload asset is missing: $source"
    }
    $parent = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    Copy-Item -LiteralPath $source -Destination $Destination -Force
}

function New-OciMount {
    param(
        [Parameter(Mandatory)]
        [string]$Destination,
        [Parameter(Mandatory)]
        [string]$Type,
        [Parameter(Mandatory)]
        [string]$Source,
        [Parameter(Mandatory)]
        [string[]]$Options
    )

    [pscustomobject][ordered]@{
        destination = $Destination
        type = $Type
        source = $Source
        options = @($Options)
    }
}

function Initialize-InitScriptFixture {
    param(
        [Parameter(Mandatory)]
        [object]$Config,
        [Parameter(Mandatory)]
        [string]$Bundle,
        [Parameter(Mandatory)]
        [string]$ContainerRootfs,
        [Parameter(Mandatory)]
        [string]$Asset,
        [Parameter(Mandatory)]
        [string]$Scenario,
        [switch]$DelayBeforeReady
    )

    $scriptSource = Join-Path $ContainerRootfs 'opt\a3s\init.sh'
    $stateDirectory = Join-Path $Bundle 'volumes\rw'
    New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null
    Copy-WorkloadAsset -Name $Asset -Destination $scriptSource

    $stateTarget = Join-Path $ContainerRootfs 'mnt\rw'
    New-Item -ItemType Directory -Path $stateTarget -Force | Out-Null

    $Config.mounts = @($Config.mounts) + @(
        (New-OciMount -Destination '/mnt/rw' -Type 'none' `
            -Source 'volumes/rw' -Options @('bind', 'rw'))
    )
    $Config.process.args = @('/bin/sh', '/opt/a3s/init.sh')
    $Config.process.env = @($Config.process.env) + @(
        "A3S_INIT_SCENARIO=$Scenario"
    )
    if ($DelayBeforeReady) {
        $Config.process.env += 'A3S_INIT_DELAY_SECONDS=1'
    }

    [pscustomobject]@{
        Evidence = Join-Path $stateDirectory 'lifecycle.log'
        Source = $scriptSource
        ReadOnlySource = $null
        Scratch = $null
        RoundTrip = $null
    }
}

function Assert-TextEvidence {
    param(
        [Parameter(Mandatory)]
        [string]$Label,
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string[]]$RequiredFragments
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label did not produce evidence: $Path"
    }
    $text = Get-Content -LiteralPath $Path -Raw
    foreach ($fragment in $RequiredFragments) {
        if (-not $text.Contains($fragment)) {
            throw "$Label evidence did not contain: $fragment"
        }
    }
}

function New-SoakFixture {
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [ValidateSet(
            'positive',
            'mounts-without-namespace',
            'apparmor-profile',
            'mount-label',
            'seccomp-multi-arch',
            'ambiguous-propagation',
            'additional-root-mount',
            'bind-without-source',
            'username',
            'net-devices',
            'missing-mount-source',
            'network-isolated',
            'network-inherited',
            'storage-matrix',
            'init-script',
            'init-script-failure'
        )]
        [string]$Variant = 'positive'
    )

    $fixture = Join-Path $script:fixturesDirectory $Name
    if (Test-Path -LiteralPath $fixture) {
        throw "Refusing to overwrite an existing fixture: $fixture"
    }
    $vmRootfs = Join-Path $fixture 'vm'
    $bundle = Join-Path $vmRootfs 'bundle'
    $containerRootfs = Join-Path $bundle 'rootfs'
    New-Item -ItemType Directory -Path $vmRootfs | Out-Null
    & $script:tar -xf $script:rootfsArchive -C $vmRootfs
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to extract VM rootfs for fixture $Name"
    }
    New-Item -ItemType Directory -Path $containerRootfs | Out-Null
    & $script:tar -xf $script:rootfsArchive -C $containerRootfs
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to extract container rootfs for fixture $Name"
    }
    Copy-Item -LiteralPath $script:agent `
        -Destination (Join-Path $vmRootfs 'usr\bin\a3s-oci-agent') -Force

    $config = Get-Content -LiteralPath $script:fixtureConfig -Raw | ConvertFrom-Json
    $config.linux.cgroupsPath = "a3s-oci-windows-soak-$Name"
    $scenarioMetadata = [pscustomobject]@{
        Evidence = $null
        Source = $null
        ReadOnlySource = $null
        Scratch = $null
        RoundTrip = $null
    }
    switch ($Variant) {
        'mounts-without-namespace' {
            $config.linux.namespaces = @(
                $config.linux.namespaces | Where-Object { $_.type -ne 'mount' }
            )
        }
        'apparmor-profile' {
            $config.process | Add-Member -NotePropertyName apparmorProfile `
                -NotePropertyValue 'a3s-windows-soak'
        }
        'mount-label' {
            $config.linux | Add-Member -NotePropertyName mountLabel `
                -NotePropertyValue 'system_u:object_r:container_file_t:s0'
        }
        'seccomp-multi-arch' {
            $seccomp = [pscustomobject][ordered]@{
                defaultAction = 'SCMP_ACT_ALLOW'
                architectures = @('SCMP_ARCH_X86_64', 'SCMP_ARCH_AARCH64')
            }
            $config.linux | Add-Member -NotePropertyName seccomp `
                -NotePropertyValue $seccomp
        }
        'ambiguous-propagation' {
            $source = Join-Path $bundle 'volumes\ambiguous'
            $target = Join-Path $containerRootfs 'mnt\ambiguous'
            New-Item -ItemType Directory -Path $source, $target -Force | Out-Null
            $config.mounts = @($config.mounts) + @(
                (New-OciMount -Destination '/mnt/ambiguous' -Type 'none' `
                    -Source 'volumes/ambiguous' `
                    -Options @('bind', 'private', 'slave'))
            )
        }
        'additional-root-mount' {
            $config.mounts = @($config.mounts) + @(
                (New-OciMount -Destination '/' -Type 'tmpfs' -Source 'tmpfs' `
                    -Options @('nosuid', 'nodev'))
            )
        }
        'bind-without-source' {
            $target = Join-Path $containerRootfs 'mnt\missing-bind-source'
            New-Item -ItemType Directory -Path $target -Force | Out-Null
            $config.mounts = @($config.mounts) + @(
                [pscustomobject][ordered]@{
                    destination = '/mnt/missing-bind-source'
                    type = 'none'
                    options = @('bind', 'ro')
                }
            )
        }
        'username' {
            $config.process.user | Add-Member -NotePropertyName username `
                -NotePropertyValue 'root'
        }
        'net-devices' {
            $netDevices = [pscustomobject][ordered]@{
                eth0 = [pscustomobject][ordered]@{
                    name = 'container-eth0'
                }
            }
            $config.linux | Add-Member -NotePropertyName netDevices `
                -NotePropertyValue $netDevices
        }
        'missing-mount-source' {
            $target = Join-Path $containerRootfs 'mnt\missing-source'
            New-Item -ItemType Directory -Path $target -Force | Out-Null
            $config.mounts = @($config.mounts) + @(
                (New-OciMount -Destination '/mnt/missing-source' -Type 'none' `
                    -Source 'volumes/does-not-exist' -Options @('bind', 'ro'))
            )
        }
        'network-isolated' {
            $target = Join-Path $containerRootfs 'opt\a3s\network-isolated.sh'
            Copy-WorkloadAsset -Name 'network-isolated.sh' -Destination $target
            $config.process.args = @('/bin/sh', '/opt/a3s/network-isolated.sh')
            $scenarioMetadata.Evidence = Join-Path (
                $containerRootfs
            ) '.a3s-network-evidence'
        }
        'network-inherited' {
            $config.linux.namespaces = @(
                $config.linux.namespaces |
                    Where-Object { $_.type -ne 'network' }
            )
            $target = Join-Path $containerRootfs 'opt\a3s\network-inherited.sh'
            Copy-WorkloadAsset -Name 'network-inherited.sh' -Destination $target
            $config.process.args = @('/bin/sh', '/opt/a3s/network-inherited.sh')
            $scenarioMetadata.Evidence = Join-Path (
                $containerRootfs
            ) '.a3s-network-evidence'
        }
        'storage-matrix' {
            $rwSource = Join-Path $bundle 'volumes\rw'
            $readOnlySource = Join-Path $bundle 'volumes\readonly'
            New-Item -ItemType Directory -Path $rwSource, $readOnlySource `
                -Force | Out-Null
            $sentinel = Join-Path $readOnlySource 'sentinel.txt'
            Write-Utf8Text -Path $sentinel -Text 'read-only-volume-v1'

            $scriptTarget = Join-Path $containerRootfs 'opt\a3s\storage-matrix.sh'
            Copy-WorkloadAsset -Name 'storage-matrix.sh' -Destination $scriptTarget
            $rwTarget = Join-Path $containerRootfs 'mnt\rw'
            $readOnlyTarget = Join-Path $containerRootfs 'mnt\readonly'
            New-Item -ItemType Directory -Path $rwTarget, $readOnlyTarget `
                -Force | Out-Null

            $config.mounts = @($config.mounts) + @(
                (New-OciMount -Destination '/mnt/rw' -Type 'none' `
                    -Source 'volumes/rw' -Options @('bind', 'rw')),
                (New-OciMount -Destination '/mnt/readonly' -Type 'none' `
                    -Source 'volumes/readonly' -Options @('bind', 'ro'))
            )
            $config.process.args = @('/bin/sh', '/opt/a3s/storage-matrix.sh')
            $scenarioMetadata.Evidence = Join-Path $rwSource 'lifecycle.log'
            $scenarioMetadata.ReadOnlySource = $sentinel
            $scenarioMetadata.RoundTrip = Join-Path $rwSource 'round-trip.txt'
        }
        'init-script' {
            $scenarioMetadata = Initialize-InitScriptFixture -Config $config `
                -Bundle $bundle -ContainerRootfs $containerRootfs `
                -Asset 'init-volume.sh' -Scenario 'volume-init' -DelayBeforeReady
        }
        'init-script-failure' {
            $scenarioMetadata = Initialize-InitScriptFixture -Config $config `
                -Bundle $bundle -ContainerRootfs $containerRootfs `
                -Asset 'init-failure.sh' -Scenario 'expected-failure'
        }
    }
    Write-JsonFile -Path (Join-Path $bundle 'config.json') -Value $config

    [pscustomobject]@{
        Name = $Name
        Variant = $Variant
        Root = $fixture
        VmRootfs = $vmRootfs
        Bundle = $bundle
        Marker = Join-Path $containerRootfs '.a3s-oci-create-start-smoke'
        Scenario = $scenarioMetadata
    }
}

function New-SecondBundle {
    param(
        [Parameter(Mandatory)]
        [object]$Fixture,
        [Parameter(Mandatory)]
        [string]$Name
    )

    $bundle = Join-Path $Fixture.VmRootfs $Name
    $containerRootfs = Join-Path $bundle 'rootfs'
    if (Test-Path -LiteralPath $bundle) {
        throw "Refusing to overwrite an existing second bundle: $bundle"
    }
    New-Item -ItemType Directory -Path $containerRootfs -Force | Out-Null
    & $script:tar -xf $script:rootfsArchive -C $containerRootfs
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to extract the second container rootfs for $Name"
    }
    $config = Get-Content -LiteralPath $script:fixtureConfig -Raw | ConvertFrom-Json
    $config.linux.cgroupsPath = "a3s-oci-windows-soak-$Name"
    Write-JsonFile -Path (Join-Path $bundle 'config.json') -Value $config
    $bundle
}

function Get-FixtureAudit {
    param(
        [Parameter(Mandatory)]
        [object]$Fixture
    )

    $logs = @(Get-ChildItem -LiteralPath $Fixture.VmRootfs -File -Filter '*.log' `
        -Force -ErrorAction SilentlyContinue)
    $tokenHits = @(
        $logs | Select-String -SimpleMatch 'A3S_OCI_AGENT_SESSION_TOKEN='
    )
    $bootstrapDirectories = @(
        Get-ChildItem -LiteralPath $Fixture.VmRootfs -Directory -Force |
            Where-Object { $_.Name -like '.a3s-oci-bootstrap-*' }
    )
    $runtimeParent = Join-Path $Fixture.VmRootfs 'run'
    $runtimeDirectories = @()
    if (Test-Path -LiteralPath $runtimeParent -PathType Container) {
        $runtimeDirectories = @(
            Get-ChildItem -LiteralPath $runtimeParent -Directory -Force |
                Where-Object { $_.Name -like 'a3s-oci-agent-*' }
        )
    }
    [int64]$logBytes = 0
    foreach ($log in $logs) {
        $logBytes += $log.Length
    }
    [pscustomobject]@{
        BootstrapDirectories = $bootstrapDirectories.Count
        RuntimeDirectories = $runtimeDirectories.Count
        DirectTokenLogHits = $tokenHits.Count
        MarkerExists = Test-Path -LiteralPath $Fixture.Marker
        RootLogBytes = [int64]$logBytes
    }
}

function Assert-RuntimeAudit {
    param(
        [Parameter(Mandatory)]
        [string]$Label,
        [Parameter(Mandatory)]
        [object]$Audit
    )

    if ($Audit.BootstrapDirectories -ne 0) {
        throw "$Label left $($Audit.BootstrapDirectories) bootstrap directories"
    }
    if ($Audit.RuntimeDirectories -ne 0) {
        throw "$Label left $($Audit.RuntimeDirectories) guest runtime directories"
    }
    if ($Audit.DirectTokenLogHits -ne 0) {
        throw "$Label exposed the direct session-token environment entry in guest logs"
    }
}

function Get-A3sProcesses {
    @(
        Get-Process -Name 'a3s-oci', 'a3s-oci-krun-shim' `
            -ErrorAction SilentlyContinue |
            ForEach-Object {
                $processIdentifier = $null
                $processName = $null
                $executablePath = $null
                try {
                    $processIdentifier = $_.Id
                    $processName = $_.ProcessName
                    $executablePath = $_.Path
                }
                catch {
                    # A process may exit while its image path is inspected.
                }
                if ($null -ne $processIdentifier -and
                    -not [string]::IsNullOrWhiteSpace($processName)) {
                    [pscustomobject]@{
                        ProcessId = $processIdentifier
                        Name = "$processName.exe"
                        ExecutablePath = $executablePath
                    }
                }
            }
    )
}

function Wait-ForA3sProcessesToExit {
    param([int]$TimeoutSeconds = 20)

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $processes = @(Get-A3sProcesses)
        if ($processes.Count -eq 0) {
            return @()
        }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $deadline)
    @(Get-A3sProcesses)
}

function Assert-NoA3sProcesses {
    param([Parameter(Mandatory)][string]$Label)

    $residual = @(Wait-ForA3sProcessesToExit)
    if ($residual.Count -gt 0) {
        $description = ($residual | ForEach-Object {
            '{0}:{1}' -f $_.Name, $_.ProcessId
        }) -join ', '
        throw "$Label leaked host processes: $description"
    }
}

function Start-OciSmoke {
    param(
        [Parameter(Mandatory)]
        [object]$Fixture,
        [Parameter(Mandatory)]
        [string]$Console
    )

    Start-CapturedProcess -FilePath $script:cli -Arguments @(
        'oci-vm-smoke',
        '--shim', $script:shim,
        '--vm-rootfs', $Fixture.VmRootfs,
        '--bundle', $Fixture.Bundle,
        '--console', $Console
    )
}

function Start-MultiContainerSmoke {
    param(
        [Parameter(Mandatory)]
        [object]$Fixture,
        [Parameter(Mandatory)]
        [string]$BundleB,
        [Parameter(Mandatory)]
        [string]$Console
    )

    Start-CapturedProcess -FilePath $script:cli -Arguments @(
        'windows-oci-vm-multi-container-smoke',
        '--shim', $script:shim,
        '--vm-rootfs', $Fixture.VmRootfs,
        '--bundle-a', $Fixture.Bundle,
        '--bundle-b', $BundleB,
        '--console', $Console
    )
}

function Start-LifecycleFaultSmoke {
    param(
        [Parameter(Mandatory)]
        [object]$Fixture,
        [Parameter(Mandatory)]
        [string]$Console,
        [Parameter(Mandatory)]
        [ValidateSet('after-create', 'after-start', 'after-kill')]
        [string]$Fault
    )

    Start-CapturedProcess -FilePath $script:cli -Arguments @(
        'oci-vm-fault-cleanup',
        '--shim', $script:shim,
        '--vm-rootfs', $Fixture.VmRootfs,
        '--bundle', $Fixture.Bundle,
        '--console', $Console,
        '--fault-after', $Fault
    )
}

function Complete-OciSmoke {
    param(
        [Parameter(Mandatory)]
        [object]$Running,
        [Parameter(Mandatory)]
        [string]$Label
    )

    $completed = Complete-CapturedProcess -Running $Running
    Save-ProcessEvidence -Label $Label -Completed $completed
    $report = $null
    if (-not [string]::IsNullOrWhiteSpace($completed.Stdout)) {
        try {
            $report = $completed.Stdout | ConvertFrom-Json
        }
        catch {
            throw "$Label emitted invalid JSON: $($_.Exception.Message)"
        }
    }
    [pscustomobject]@{
        Completed = $completed
        Report = $report
    }
}

function Assert-MultiContainerReport {
    param(
        [Parameter(Mandatory)]
        [string]$Label,
        [Parameter(Mandatory)]
        [object]$Result
    )

    if ($Result.Completed.ExitCode -ne 0 -or $null -eq $Result.Report) {
        throw "$Label did not complete successfully"
    }
    if ($Result.Report.schema_version -ne `
            'a3s.oci.windows-oci-vm-multi-container-smoke.v1' -or
        $Result.Report.platform -ne 'windows' -or
        $Result.Report.status -ne 'available' -or
        $Result.Report.bundles_loaded -ne $true -or
        $Result.Report.markers_removed -ne $true -or
        $Result.Report.guest_runtime_clean -ne $true -or
        $Result.Report.bridge.status -ne 'available') {
        throw "$Label did not retain complete Windows multi-container evidence"
    }
}

function Assert-LifecycleFaultReport {
    param(
        [Parameter(Mandatory)]
        [string]$Label,
        [Parameter(Mandatory)]
        [object]$Result,
        [Parameter(Mandatory)]
        [string]$Fault
    )

    if ($Result.Completed.ExitCode -ne 0 -or $null -eq $Result.Report) {
        throw "$Label did not complete successfully"
    }
    if ($Result.Report.schema_version -ne 'a3s.oci.oci-vm-fault-cleanup.v4' -or
        $Result.Report.platform -ne 'windows' -or
        $Result.Report.status -ne 'available' -or
        $Result.Report.lifecycle.requested_fault -ne $Fault -or
        $Result.Report.lifecycle.injected_fault -ne $Fault -or
        $Result.Report.lifecycle.normal_delete_attempted -ne $false -or
        $Result.Report.marker_removed -ne $true -or
        $Result.Report.guest_runtime_clean -ne $true -or
        $Result.Report.bridge.status -ne 'available') {
        throw "$Label did not retain exact lifecycle fault-cleanup evidence"
    }
}

function Assert-PositiveReport {
    param(
        [Parameter(Mandatory)]
        [string]$Label,
        [Parameter(Mandatory)]
        [object]$Result
    )

    if ($Result.Completed.ExitCode -ne 0) {
        throw "$Label failed with exit code $($Result.Completed.ExitCode)"
    }
    if ($null -eq $Result.Report) {
        throw "$Label emitted no report"
    }
    if ($Result.Report.schema_version -ne 'a3s.oci.oci-vm-smoke.v8' -or
        $Result.Report.platform -ne 'windows' -or
        $Result.Report.status -ne 'available') {
        throw "$Label did not return an available Windows v8 report"
    }
    $trueFields = @(
        'bundle_loaded',
        'create_returned_created',
        'create_replayed',
        'marker_absent_after_create',
        'start_released',
        'running_observed',
        'processes_verified',
        'process_io_verified',
        'terminal_io_verified',
        'resources_updated',
        'stats_verified',
        'pause_froze_workload',
        'resume_advanced_workload',
        'kill_delivered',
        'kill_replayed',
        'wait_timeout_enforced',
        'wait_replayed',
        'stopped_observed',
        'marker_verified',
        'delete_succeeded',
        'delete_replayed',
        'state_missing_after_delete',
        'marker_removed',
        'guest_runtime_clean'
    )
    foreach ($field in $trueFields) {
        if ($Result.Report.$field -ne $true) {
            throw "$Label report field is not true: $field"
        }
    }
    if ($Result.Report.created_pid -le 0) {
        throw "$Label returned an invalid guest init PID"
    }
    if ($Result.Report.bridge.status -ne 'available' -or
        $Result.Report.bridge.protocol_negotiated -ne $true -or
        $Result.Report.bridge.shim_report_verified -ne $true -or
        $Result.Report.bridge.selected_protocol -ne 8) {
        throw "$Label did not retain a successful authenticated bridge"
    }
    $operations = @($Result.Report.bridge.advertised_operations) -join ','
    $expectedOperations = (
        'create,state,start,kill,delete,wait,exec,signal-process,' +
        'wait-process,pause,resume,processes,update,stats,read-output,' +
        'write-stdin,close-stdin,resize'
    )
    if ($operations -ne $expectedOperations) {
        throw "$Label advertised unexpected guest operations: $operations"
    }
}

function Invoke-PositiveRun {
    param(
        [Parameter(Mandatory)]
        [object]$Fixture,
        [Parameter(Mandatory)]
        [string]$Label
    )

    $console = Join-Path $script:evidenceDirectory "$Label.console.log"
    $running = Start-OciSmoke -Fixture $Fixture -Console $console
    $run = Complete-OciSmoke -Running $running -Label $Label
    Assert-PositiveReport -Label $Label -Result $run
    $audit = Get-FixtureAudit -Fixture $Fixture
    Assert-RuntimeAudit -Label $Label -Audit $audit
    if ($audit.MarkerExists) {
        throw "$Label left the fixed workload marker"
    }
    Assert-NoA3sProcesses -Label $Label
    [pscustomobject]@{
        Result = $run
        Audit = $audit
        Console = $console
    }
}

function Wait-ForShimChild {
    param(
        [Parameter(Mandatory)]
        [int]$OwnerProcessId,
        [int]$TimeoutSeconds = 15
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $child = @(
            Get-A3sProcesses |
                Where-Object {
                    $_.Name -eq 'a3s-oci-krun-shim.exe' -and
                    [StringComparer]::OrdinalIgnoreCase.Equals(
                        $_.ExecutablePath,
                        $script:shim
                    )
                }
        ) | Select-Object -First 1
        if ($null -ne $child) {
            return $child
        }
        Start-Sleep -Milliseconds 10
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Timed out waiting for shim child of CLI process $OwnerProcessId"
}

function Test-ExactShimProcess {
    param([Parameter(Mandatory)][int]$ProcessId)

    $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        return $false
    }
    $path = $null
    try {
        $path = $process.Path
    }
    catch {
        return $false
    }
    [StringComparer]::OrdinalIgnoreCase.Equals($path, $script:shim)
}

function Get-VerificationFailures {
    $failures = New-Object 'System.Collections.Generic.List[string]'

    if ($script:result -ne 'pass') {
        $failures.Add("runner result is $($script:result)")
    }
    if ($script:startInventory.Count -ne 0) {
        $failures.Add(
            "start inventory contains $($script:startInventory.Count) A3S processes"
        )
    }
    if ($script:finalInventory.Count -ne 0) {
        $failures.Add(
            "final inventory contains $($script:finalInventory.Count) A3S processes"
        )
    }
    if ($script:capabilityResults.Count -ne 2) {
        $failures.Add(
            "capability probe count is $($script:capabilityResults.Count), expected 2"
        )
    }
    foreach ($capability in $script:capabilityResults) {
        if ((Get-RecordValue -Record $capability -Name 'result') -ne 'pass') {
            $failures.Add(
                "capability probe failed: " +
                (Get-RecordValue -Record $capability -Name 'capability')
            )
        }
    }

    if ($script:completedIterations -le 0) {
        $failures.Add('no serial lifecycle iteration completed')
    }
    if ($DurationSeconds -eq 0 -and
        $script:completedIterations -ne $Iterations) {
        $failures.Add(
            "serial lifecycle count is $($script:completedIterations), " +
            "expected $Iterations"
        )
    }
    if ($Iterations -gt 0 -and
        $script:completedIterations -gt $Iterations) {
        $failures.Add(
            "serial lifecycle count exceeded the requested cap $Iterations"
        )
    }

    $expectedParallelRuns = if ($SkipParallel) {
        0
    }
    else {
        $ParallelWaves * $Parallelism
    }
    if ($script:completedParallelRuns -ne $expectedParallelRuns) {
        $failures.Add(
            "parallel run count is $($script:completedParallelRuns), " +
            "expected $expectedParallelRuns"
        )
    }
    if ($script:completedMultiContainerRuns -ne $MultiContainerIterations) {
        $failures.Add(
            "multi-container run count is $($script:completedMultiContainerRuns), " +
            "expected $MultiContainerIterations"
        )
    }

    $expectedLifecycleFaults = if ($SkipFaultInjection) {
        0
    }
    else {
        3 * $LifecycleFaultIterations
    }
    if ($script:completedLifecycleFaults -ne $expectedLifecycleFaults) {
        $failures.Add(
            "lifecycle fault count is $($script:completedLifecycleFaults), " +
            "expected $expectedLifecycleFaults"
        )
    }

    $expectedWorkloadCases = if ($SkipWorkloadCases) {
        0
    }
    else {
        $WorkloadCases.Count * $WorkloadIterations
    }
    if ($script:completedWorkloadCases -ne $expectedWorkloadCases) {
        $failures.Add(
            "workload case count is $($script:completedWorkloadCases), " +
            "expected $expectedWorkloadCases"
        )
    }

    $expectedNegativeCases = if ($SkipNegativeCases) { 0 } else { 10 }
    if ($script:completedNegatives -ne $expectedNegativeCases) {
        $failures.Add(
            "negative case count is $($script:completedNegatives), " +
            "expected $expectedNegativeCases"
        )
    }

    $expectedOwnerFaults = if ($SkipFaultInjection) {
        0
    }
    else {
        $OwnerKillDelayMilliseconds.Count
    }
    if ($script:completedFaults -ne $expectedOwnerFaults) {
        $failures.Add(
            "owner-kill fault count is $($script:completedFaults), " +
            "expected $expectedOwnerFaults"
        )
    }

    $expectedOperations = (
        $script:completedIterations +
        $script:completedParallelRuns +
        $script:completedMultiContainerRuns +
        $script:completedLifecycleFaults +
        $script:completedWorkloadCases +
        $script:completedNegatives +
        $script:completedFaults
    )
    if ($script:samples.Count -ne $expectedOperations) {
        $failures.Add(
            "operation sample count is $($script:samples.Count), " +
            "expected $expectedOperations"
        )
    }
    foreach ($sample in $script:samples) {
        $kind = Get-RecordValue -Record $sample -Name 'kind'
        if ((Get-RecordValue -Record $sample -Name 'result') -ne 'pass') {
            $failures.Add("operation sample failed: $kind")
        }
        if ([int64](Get-RecordValue -Record $sample `
                -Name 'peak_working_set_bytes') -le 0) {
            $failures.Add("operation captured no host working-set sample: $kind")
        }
        if ($kind -eq 'owner-kill' -and
            [int64](Get-RecordValue -Record $sample -Name 'shim_exit_ms') -le 0) {
            $failures.Add('owner-kill sample captured no shim exit duration')
        }
    }

    $maxPeakWorkingSet = Get-SampleMaximum -Name 'peak_working_set_bytes'
    $maxPeakLimit = [int64]$MaxHostProcessWorkingSetMiB * 1MB
    if ($script:samples.Count -gt 0 -and $maxPeakWorkingSet -le 0) {
        $failures.Add('no host process working-set sample was captured')
    }
    if ($maxPeakWorkingSet -gt $maxPeakLimit) {
        $failures.Add(
            "peak host process working set $maxPeakWorkingSet exceeds " +
            "$maxPeakLimit bytes"
        )
    }

    $serialLogGrowth = (
        $script:serialFinalLogBytes - $script:serialInitialLogBytes
    )
    $serialLogLimit = [int64]$MaxSerialLogGrowthMiB * 1MB
    if ($serialLogGrowth -lt 0 -or $serialLogGrowth -gt $serialLogLimit) {
        $failures.Add(
            "serial root log growth $serialLogGrowth is outside 0.." +
            "$serialLogLimit bytes"
        )
    }

    $maxOwnerShimExit = Get-SampleMaximum -Name 'shim_exit_ms'
    if ($maxOwnerShimExit -gt 20000) {
        $failures.Add(
            "owner-bound shim exit took $maxOwnerShimExit ms, limit is 20000 ms"
        )
    }

    @($failures)
}

function Write-Summary {
    $finishedAt = [DateTime]::UtcNow
    $ownerKillDelays = New-Object 'System.Collections.Generic.List[int]'
    if (-not $SkipFaultInjection) {
        foreach ($delay in $OwnerKillDelayMilliseconds) {
            $ownerKillDelays.Add($delay)
        }
    }
    Write-EvidenceTables
    $summary = [ordered]@{
        schema = 'a3s.oci.windows-whpx-soak.v2'
        run_id = $script:runId
        result = $script:result
        verification = $script:verification
        verification_failures = $script:verificationFailures
        commit = $script:commit
        worktree_dirty = $script:worktreeStatus.Count -gt 0
        rootfs_archive = $script:rootfsArchive
        rootfs_archive_sha256 = $script:rootfsArchiveSha256
        guest_agent = $script:agent
        guest_agent_sha256 = $script:agentSha256
        native_krun = $script:krunDll
        native_krun_sha256 = $script:krunDllSha256
        started_at = $script:startedAt.ToString('o')
        soak_started_at = if ($null -eq $script:soakStartedAt) {
            $null
        }
        else {
            $script:soakStartedAt.ToString('o')
        }
        finished_at = $finishedAt.ToString('o')
        duration_seconds = [Math]::Round(
            ($finishedAt - $script:startedAt).TotalSeconds,
            3
        )
        requested_iterations = $Iterations
        requested_duration_seconds = $DurationSeconds
        completed_iterations = $script:completedIterations
        requested_parallel_waves = if ($SkipParallel) { 0 } else { $ParallelWaves }
        parallelism = $Parallelism
        requested_parallel_runs = if ($SkipParallel) {
            0
        }
        else {
            $ParallelWaves * $Parallelism
        }
        completed_parallel_runs = $script:completedParallelRuns
        requested_multi_container_runs = $MultiContainerIterations
        completed_multi_container_runs = $script:completedMultiContainerRuns
        requested_lifecycle_faults = if ($SkipFaultInjection) {
            0
        }
        else {
            3 * $LifecycleFaultIterations
        }
        completed_lifecycle_faults = $script:completedLifecycleFaults
        requested_workload_cases = if ($SkipWorkloadCases) {
            0
        }
        else {
            $WorkloadCases.Count * $WorkloadIterations
        }
        completed_workload_cases = $script:completedWorkloadCases
        requested_negative_cases = if ($SkipNegativeCases) { 0 } else { 10 }
        owner_kill_delays_ms = $ownerKillDelays
        requested_owner_kill_faults = $ownerKillDelays.Count
        completed_owner_kill_faults = $script:completedFaults
        completed_negative_cases = $script:completedNegatives
        command_timeout_seconds = $CommandTimeoutSeconds
        start_inventory_processes = $script:startInventory.Count
        final_inventory_processes = $script:finalInventory.Count
        max_host_process_working_set_bytes = (
            Get-SampleMaximum -Name 'peak_working_set_bytes'
        )
        max_host_process_working_set_limit_bytes = (
            [int64]$MaxHostProcessWorkingSetMiB * 1MB
        )
        max_owner_shim_exit_ms = Get-SampleMaximum -Name 'shim_exit_ms'
        owner_shim_exit_limit_ms = 20000
        serial_root_log_growth_bytes = (
            $script:serialFinalLogBytes - $script:serialInitialLogBytes
        )
        serial_root_log_growth_limit_bytes = (
            [int64]$MaxSerialLogGrowthMiB * 1MB
        )
        failure = $script:failure
        evidence_contract = @(
            'host.json',
            'inventory-start.json',
            'inventory-final.json',
            'capability-results.tsv',
            'operations.tsv',
            'resource-samples.tsv',
            'summary.json',
            'verify.out'
        )
        samples = $script:samples
    }
    Write-JsonFile -Path (Join-Path $script:evidenceDirectory 'summary.json') `
        -Value $summary
}

try {
    $preexisting = @(Get-A3sProcesses)
    $startInventory = $preexisting
    Write-JsonFile `
        -Path (Join-Path $evidenceDirectory 'inventory-start.json') `
        -Value @($startInventory)
    if ($preexisting.Count -gt 0) {
        $description = ($preexisting | ForEach-Object {
            '{0}:{1}' -f $_.Name, $_.ProcessId
        }) -join ', '
        throw "Refusing to start with active A3S OCI processes: $description"
    }

    $commit = (& git -C $repositoryRoot rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to resolve the repository commit.'
    }
    $worktreeStatus = @(& git -C $repositoryRoot status --porcelain)
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to inspect the repository worktree.'
    }
    $rootfsArchiveSha256 = (
        Get-FileHash -LiteralPath $rootfsArchive -Algorithm SHA256
    ).Hash.ToLowerInvariant()

    if (-not $SkipBuild) {
        Invoke-LoggedNative -Label 'build-guest-agent' -FilePath 'cargo.exe' `
            -Arguments @(
                'zigbuild',
                '-p', 'a3s-oci-agent',
                '--release',
                '--target', 'x86_64-unknown-linux-musl'
            )
        Invoke-LoggedNative -Label 'build-windows' -FilePath 'cargo.exe' `
            -Arguments @('build', '-p', 'a3s-oci-cli', '-p', 'a3s-oci-krun')
    }
    foreach ($path in @($cli, $shim, $krunDll, $agent)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required soak binary is missing: $path"
        }
    }
    $agentSha256 = (
        Get-FileHash -LiteralPath $agent -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    $krunDllSha256 = (
        Get-FileHash -LiteralPath $krunDll -Algorithm SHA256
    ).Hash.ToLowerInvariant()

    $operatingSystem = Get-ItemProperty `
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    Write-JsonFile -Path (Join-Path $evidenceDirectory 'host.json') -Value ([ordered]@{
        caption = $operatingSystem.ProductName
        display_version = $operatingSystem.DisplayVersion
        version = [Environment]::OSVersion.Version.ToString()
        build_number = $operatingSystem.CurrentBuildNumber
        update_build_revision = $operatingSystem.UBR
        architecture = $env:PROCESSOR_ARCHITECTURE
        logical_processors = [Environment]::ProcessorCount
        native_krun = $krunDll
        native_krun_sha256 = $krunDllSha256
    })

    $probe = Start-CapturedProcess -FilePath $cli -Arguments @('whpx-smoke')
    $probe = Complete-CapturedProcess -Running $probe
    Save-ProcessEvidence -Label 'whpx-smoke' -Completed $probe
    $probeReport = $probe.Stdout | ConvertFrom-Json
    if ($probe.ExitCode -ne 0 -or $probeReport.status -ne 'available') {
        throw 'The WHPX partition smoke is unavailable.'
    }
    $capabilityResults += [ordered]@{
        capability = 'whpx-partition'
        result = 'pass'
        status = $probeReport.status
        exit_code = $probe.ExitCode
        duration_ms = $probe.DurationMilliseconds
    }
    $context = Start-CapturedProcess -FilePath $shim -Arguments @('context-smoke')
    $context = Complete-CapturedProcess -Running $context
    Save-ProcessEvidence -Label 'context-smoke' -Completed $context
    $contextReport = $context.Stdout | ConvertFrom-Json
    if ($context.ExitCode -ne 0 -or $contextReport.status -ne 'available') {
        throw 'The libkrun context smoke is unavailable.'
    }
    $capabilityResults += [ordered]@{
        capability = 'libkrun-context'
        result = 'pass'
        status = $contextReport.status
        exit_code = $context.ExitCode
        duration_ms = $context.DurationMilliseconds
    }
    Assert-NoA3sProcesses -Label 'host probes'

    $serialFixture = New-SoakFixture -Name 'serial'
    $serialInitialLogBytes = (Get-FixtureAudit -Fixture $serialFixture).RootLogBytes
    $soakStartedAt = [DateTime]::UtcNow
    while ($true) {
        if ($Iterations -gt 0 -and $completedIterations -ge $Iterations) {
            break
        }
        if ($DurationSeconds -gt 0 -and
            ([DateTime]::UtcNow - $soakStartedAt).TotalSeconds -ge $DurationSeconds) {
            break
        }

        $iteration = $completedIterations + 1
        $label = 'serial-{0:D4}' -f $iteration
        Write-Host "Windows WHPX serial soak: $label"
        $run = Invoke-PositiveRun -Fixture $serialFixture -Label $label
        $serialFinalLogBytes = $run.Audit.RootLogBytes
        $samples += [ordered]@{
            kind = 'serial-positive'
            iteration = $iteration
            result = 'pass'
            exit_code = $run.Result.Completed.ExitCode
            duration_ms = $run.Result.Completed.DurationMilliseconds
            peak_working_set_bytes = $run.Result.Completed.PeakWorkingSetBytes
            root_log_bytes = $run.Audit.RootLogBytes
            console = $run.Console
        }
        $completedIterations = $iteration
        Write-Summary
    }

    for (
        $multiIteration = 1;
        $multiIteration -le $MultiContainerIterations;
        $multiIteration++
    ) {
        $label = 'multi-container-{0:D3}' -f $multiIteration
        Write-Host "Windows WHPX multi-container soak: $label"
        $fixture = New-SoakFixture -Name $label
        $bundleB = New-SecondBundle -Fixture $fixture `
            -Name ('bundle-b-{0:D3}' -f $multiIteration)
        $console = Join-Path $evidenceDirectory "$label.console.log"
        $running = Start-MultiContainerSmoke -Fixture $fixture `
            -BundleB $bundleB -Console $console
        $run = Complete-OciSmoke -Running $running -Label $label
        Assert-MultiContainerReport -Label $label -Result $run
        $audit = Get-FixtureAudit -Fixture $fixture
        Assert-RuntimeAudit -Label $label -Audit $audit
        Assert-NoA3sProcesses -Label $label
        $samples += [ordered]@{
            kind = 'multi-container'
            iteration = $multiIteration
            result = 'pass'
            exit_code = $run.Completed.ExitCode
            duration_ms = $run.Completed.DurationMilliseconds
            peak_working_set_bytes = $run.Completed.PeakWorkingSetBytes
            root_log_bytes = $audit.RootLogBytes
            console = $console
        }
        $completedMultiContainerRuns++
        Write-Summary
    }

    if (-not $SkipFaultInjection) {
        $faultPoints = @('after-create', 'after-start', 'after-kill')
        for (
            $faultIteration = 1;
            $faultIteration -le $LifecycleFaultIterations;
            $faultIteration++
        ) {
            foreach ($fault in $faultPoints) {
                $label = 'lifecycle-fault-{0:D3}-{1}' -f `
                    $faultIteration, $fault
                Write-Host "Windows WHPX lifecycle cleanup fault: $label"
                $fixture = New-SoakFixture -Name $label
                $console = Join-Path $evidenceDirectory "$label.console.log"
                $running = Start-LifecycleFaultSmoke -Fixture $fixture `
                    -Console $console -Fault $fault
                $run = Complete-OciSmoke -Running $running -Label $label
                Assert-LifecycleFaultReport -Label $label -Result $run `
                    -Fault $fault
                $audit = Get-FixtureAudit -Fixture $fixture
                Assert-RuntimeAudit -Label $label -Audit $audit
                Assert-NoA3sProcesses -Label $label
                $samples += [ordered]@{
                    kind = 'lifecycle-fault'
                    iteration = $faultIteration
                    fault = $fault
                    result = 'pass'
                    exit_code = $run.Completed.ExitCode
                    duration_ms = $run.Completed.DurationMilliseconds
                    peak_working_set_bytes = (
                        $run.Completed.PeakWorkingSetBytes
                    )
                    root_log_bytes = $audit.RootLogBytes
                    console = $console
                }
                $completedLifecycleFaults++
                Write-Summary
            }
        }
    }

    if (-not $SkipParallel -and $ParallelWaves -gt 0) {
        $parallelFixtures = @()
        for ($lane = 1; $lane -le $Parallelism; $lane++) {
            $parallelFixtures += New-SoakFixture -Name ('parallel-{0:D2}' -f $lane)
        }
        for ($wave = 1; $wave -le $ParallelWaves; $wave++) {
            Write-Host "Windows WHPX parallel soak wave $wave with $Parallelism VMs"
            $runningWave = @()
            for ($lane = 1; $lane -le $Parallelism; $lane++) {
                $label = 'parallel-{0:D3}-lane-{1:D2}' -f $wave, $lane
                $console = Join-Path $evidenceDirectory "$label.console.log"
                $runningWave += [pscustomobject]@{
                    Label = $label
                    Fixture = $parallelFixtures[$lane - 1]
                    Console = $console
                    Running = Start-OciSmoke `
                        -Fixture $parallelFixtures[$lane - 1] -Console $console
                }
            }
            $completedWave = @()
            foreach ($item in $runningWave) {
                $completedWave += [pscustomobject]@{
                    Item = $item
                    Result = Complete-OciSmoke `
                        -Running $item.Running -Label $item.Label
                }
            }
            foreach ($item in $completedWave) {
                Assert-PositiveReport -Label $item.Item.Label -Result $item.Result
                $audit = Get-FixtureAudit -Fixture $item.Item.Fixture
                Assert-RuntimeAudit -Label $item.Item.Label -Audit $audit
                if ($audit.MarkerExists) {
                    throw "$($item.Item.Label) left the fixed workload marker"
                }
                $samples += [ordered]@{
                    kind = 'parallel-positive'
                    wave = $wave
                    lane = $item.Item.Fixture.Name
                    result = 'pass'
                    exit_code = $item.Result.Completed.ExitCode
                    duration_ms = $item.Result.Completed.DurationMilliseconds
                    peak_working_set_bytes = (
                        $item.Result.Completed.PeakWorkingSetBytes
                    )
                    root_log_bytes = $audit.RootLogBytes
                    console = $item.Item.Console
                }
                $completedParallelRuns++
            }
            Assert-NoA3sProcesses -Label "parallel wave $wave"
            Write-Summary
        }
    }

    if (-not $SkipWorkloadCases) {
        $positiveWorkloadCases = @(
            $WorkloadCases | Where-Object { $_ -ne 'init-script-failure' }
        )
        for (
            $workloadIteration = 1;
            $workloadIteration -le $WorkloadIterations;
            $workloadIteration++
        ) {
            foreach ($variant in $positiveWorkloadCases) {
                $label = 'workload-{0:D3}-{1}' -f $workloadIteration, $variant
                Write-Host (
                    "Windows WHPX workload case $workloadIteration/" +
                    "${WorkloadIterations}: $variant"
                )
            $fixture = New-SoakFixture -Name $label -Variant $variant
            $run = Invoke-PositiveRun -Fixture $fixture -Label $label
            switch ($variant) {
                'network-isolated' {
                    Assert-TextEvidence -Label $label `
                        -Path $fixture.Scenario.Evidence -RequiredFragments @(
                            'phase=ready',
                            'mode=isolated',
                            'self_net=',
                            'interfaces=lo',
                            'route_count=0',
                            'phase=term'
                        )
                }
                'network-inherited' {
                    Assert-TextEvidence -Label $label `
                        -Path $fixture.Scenario.Evidence -RequiredFragments @(
                            'phase=ready',
                            'mode=inherited',
                            'self_net=',
                            'interfaces=',
                            'phase=term'
                        )
                }
                'storage-matrix' {
                    Assert-TextEvidence -Label $label `
                        -Path $fixture.Scenario.Evidence -RequiredFragments @(
                            'phase=ready',
                            'readonly=verified',
                            'rw_round_trip=verified',
                            'phase=term'
                        )
                    $roundTrip = Get-Content `
                        -LiteralPath $fixture.Scenario.RoundTrip -Raw
                    if ($roundTrip -ne "rw-round-trip-v1`n") {
                        throw "$label did not persist the RW bind round trip"
                    }
                    $sentinel = Get-Content `
                        -LiteralPath $fixture.Scenario.ReadOnlySource -Raw
                    if ($sentinel -ne 'read-only-volume-v1') {
                        throw "$label mutated the read-only bind source"
                    }
                }
                'init-script' {
                    Assert-TextEvidence -Label $label `
                        -Path $fixture.Scenario.Evidence -RequiredFragments @(
                            'phase=begin',
                            'scenario=volume-init',
                            'cwd=/',
                            'state_volume=rw',
                            'phase=ready',
                            'phase=term'
                        )
                    $expectedScript = Join-Path `
                        $fixtureAssetDirectory 'init-volume.sh'
                    $sourceHash = (
                        Get-FileHash -LiteralPath $fixture.Scenario.Source `
                            -Algorithm SHA256
                    ).Hash
                    $expectedHash = (
                        Get-FileHash -LiteralPath $expectedScript -Algorithm SHA256
                    ).Hash
                    if ($sourceHash -ne $expectedHash) {
                        throw "$label mutated the init script source"
                    }
                }
            }
            $evidenceSha256 = (
                Get-FileHash -LiteralPath $fixture.Scenario.Evidence `
                    -Algorithm SHA256
            ).Hash.ToLowerInvariant()
            $samples += [ordered]@{
                kind = 'workload-positive'
                variant = $variant
                workload_iteration = $workloadIteration
                result = 'pass'
                exit_code = $run.Result.Completed.ExitCode
                duration_ms = $run.Result.Completed.DurationMilliseconds
                peak_working_set_bytes = (
                    $run.Result.Completed.PeakWorkingSetBytes
                )
                evidence = $fixture.Scenario.Evidence
                evidence_sha256 = $evidenceSha256
                root_log_bytes = $run.Audit.RootLogBytes
                console = $run.Console
            }
            $completedWorkloadCases++
            Write-Summary
            }

            if ($WorkloadCases -notcontains 'init-script-failure') {
                continue
            }
            $variant = 'init-script-failure'
            $label = 'workload-{0:D3}-{1}' -f $workloadIteration, $variant
            Write-Host (
                "Windows WHPX workload case $workloadIteration/" +
                "${WorkloadIterations}: $variant"
            )
        $fixture = New-SoakFixture -Name $label -Variant $variant
        $console = Join-Path $evidenceDirectory "$label.console.log"
        $running = Start-OciSmoke -Fixture $fixture -Console $console
        $run = Complete-OciSmoke -Running $running -Label $label
        if ($run.Completed.ExitCode -ne 2 -or $null -eq $run.Report -or
            $run.Report.status -ne 'unavailable') {
            throw "$label did not report the expected workload failure"
        }
        $failureReason = [string]$run.Report.reason
        if ($failureReason.IndexOf(
            'stopped',
            [StringComparison]::OrdinalIgnoreCase
        ) -lt 0) {
            throw "$label did not report the stopped init process"
        }
        if ($run.Report.bridge.protocol_negotiated -ne $true -or
            $run.Report.bridge.shim_report_verified -ne $true -or
            $run.Report.guest_runtime_clean -ne $true) {
            throw "$label did not cleanly stop the authenticated guest"
        }
        $audit = Get-FixtureAudit -Fixture $fixture
        Assert-RuntimeAudit -Label $label -Audit $audit
        if ($audit.MarkerExists) {
            throw "$label unexpectedly produced the ready marker"
        }
        Assert-NoA3sProcesses -Label $label
        Assert-TextEvidence -Label $label -Path $fixture.Scenario.Evidence `
            -RequiredFragments @(
                'phase=begin',
                'scenario=expected-failure',
                'phase=failure',
                'exit=42'
            )
        $samples += [ordered]@{
            kind = 'workload-expected-failure'
            variant = $variant
            workload_iteration = $workloadIteration
            result = 'pass'
            exit_code = $run.Completed.ExitCode
            duration_ms = $run.Completed.DurationMilliseconds
            peak_working_set_bytes = $run.Completed.PeakWorkingSetBytes
            evidence = $fixture.Scenario.Evidence
            reason = $failureReason
            root_log_bytes = $audit.RootLogBytes
            console = $console
        }
        $completedWorkloadCases++
        Write-Summary
        }
    }

    if (-not $SkipNegativeCases) {
        $negativeCases = @(
            [pscustomobject]@{
                Variant = 'mounts-without-namespace'
                Layer = 'guest'
                Code = 'Unsupported'
                Expected = 'mounts'
            },
            [pscustomobject]@{
                Variant = 'apparmor-profile'
                Layer = 'guest'
                Code = 'Unsupported'
                Expected = 'process.apparmorProfile'
            },
            [pscustomobject]@{
                Variant = 'mount-label'
                Layer = 'guest'
                Code = 'Unsupported'
                Expected = 'linux.mountLabel'
            },
            [pscustomobject]@{
                Variant = 'seccomp-multi-arch'
                Layer = 'guest'
                Code = 'Unsupported'
                Expected = 'linux.seccomp.architectures'
            },
            [pscustomobject]@{
                Variant = 'ambiguous-propagation'
                Layer = 'guest'
                Code = 'InvalidArgument'
                Expected = 'mounts[1].options'
            },
            [pscustomobject]@{
                Variant = 'additional-root-mount'
                Layer = 'guest'
                Code = 'Unsupported'
                Expected = 'mounts[1].destination'
            },
            [pscustomobject]@{
                Variant = 'bind-without-source'
                Layer = 'guest'
                Code = 'InvalidArgument'
                Expected = 'mounts[1].source'
            },
            [pscustomobject]@{
                Variant = 'username'
                Layer = 'host'
                Code = 'oci.platform.windows-process-field'
                Expected = 'process.user.username'
            },
            [pscustomobject]@{
                Variant = 'net-devices'
                Layer = 'guest'
                Code = 'Unsupported'
                Expected = 'linux.netDevices'
            },
            [pscustomobject]@{
                Variant = 'missing-mount-source'
                Layer = 'guest'
                Code = 'InvalidArgument'
                Expected = 'mounts[1].source'
            }
        )
        foreach ($case in $negativeCases) {
            $label = "negative-$($case.Variant)"
            Write-Host "Windows WHPX negative case: $($case.Variant)"
            $fixture = New-SoakFixture -Name $label -Variant $case.Variant
            $console = Join-Path $evidenceDirectory "$label.console.log"
            $running = Start-OciSmoke -Fixture $fixture -Console $console
            $run = Complete-OciSmoke -Running $running -Label $label
            if ($run.Completed.ExitCode -ne 2 -or $null -eq $run.Report -or
                $run.Report.status -ne 'unavailable') {
                throw "$label did not retain the expected unavailable exit contract"
            }
            if (-not ([string]$run.Report.reason).Contains($case.Expected)) {
                throw "$label did not retain rejection evidence for $($case.Expected)"
            }
            if (-not ([string]$run.Report.reason).Contains($case.Code)) {
                throw "$label did not retain typed $($case.Code) evidence"
            }
            if ($case.Layer -eq 'guest') {
                if ($run.Report.bridge.protocol_negotiated -ne $true -or
                    $run.Report.bridge.shim_report_verified -ne $true -or
                    $run.Report.guest_runtime_clean -ne $true) {
                    throw "$label did not shut down the authenticated guest cleanly"
                }
            }
            elseif ($run.Report.bridge.endpoint_bound -ne $false -or
                $run.Report.bridge.shim_spawned -ne $false) {
                throw "$label crossed the host preflight boundary"
            }
            $audit = Get-FixtureAudit -Fixture $fixture
            Assert-RuntimeAudit -Label $label -Audit $audit
            Assert-NoA3sProcesses -Label $label
            $samples += [ordered]@{
                kind = 'negative'
                variant = $case.Variant
                result = 'pass'
                exit_code = $run.Completed.ExitCode
                duration_ms = $run.Completed.DurationMilliseconds
                peak_working_set_bytes = $run.Completed.PeakWorkingSetBytes
                expected_code = $case.Code
                expected_field = $case.Expected
                rejection_layer = $case.Layer
                root_log_bytes = $audit.RootLogBytes
                console = $console
            }
            $completedNegatives++
            Write-Summary
        }
    }

    if (-not $SkipFaultInjection) {
        foreach ($delay in $OwnerKillDelayMilliseconds) {
            $label = 'owner-kill-{0:D5}ms' -f $delay
            Write-Host "Windows WHPX owner-kill fault: $delay ms after shim spawn"
            $fixture = New-SoakFixture -Name $label
            $console = Join-Path $evidenceDirectory "$label.console.log"
            $running = Start-OciSmoke -Fixture $fixture -Console $console
            $shimProcess = Wait-ForShimChild -OwnerProcessId $running.Process.Id
            if (-not [StringComparer]::OrdinalIgnoreCase.Equals(
                $shimProcess.ExecutablePath,
                $shim
            )) {
                throw "$label resolved an unexpected shim executable"
            }
            if ($delay -gt 0) {
                Start-Sleep -Milliseconds $delay
            }
            $running.Process.Refresh()
            if ($running.Process.HasExited) {
                throw "$label owner exited before fault injection"
            }
            $shimExitTimer = [Diagnostics.Stopwatch]::StartNew()
            $running.Process.Kill()
            $completed = Complete-CapturedProcess -Running $running -TimeoutSeconds 10
            Save-ProcessEvidence -Label $label -Completed $completed
            $shimDeadline = [DateTime]::UtcNow.AddSeconds(20)
            while ((Test-ExactShimProcess -ProcessId $shimProcess.ProcessId) -and
                [DateTime]::UtcNow -lt $shimDeadline) {
                Start-Sleep -Milliseconds 10
            }
            $shimExitTimer.Stop()
            if (Test-ExactShimProcess -ProcessId $shimProcess.ProcessId) {
                throw "$label left the exact shim process running"
            }
            Start-Sleep -Milliseconds 100
            $audit = Get-FixtureAudit -Fixture $fixture
            Assert-RuntimeAudit -Label $label -Audit $audit
            Assert-NoA3sProcesses -Label $label
            $samples += [ordered]@{
                kind = 'owner-kill'
                delay_ms = $delay
                result = 'pass'
                cli_pid = $completed.ProcessId
                shim_pid = $shimProcess.ProcessId
                exit_code = $completed.ExitCode
                duration_ms = $completed.DurationMilliseconds
                peak_working_set_bytes = $completed.PeakWorkingSetBytes
                shim_exit_ms = $shimExitTimer.ElapsedMilliseconds
                marker_exists = $audit.MarkerExists
                root_log_bytes = $audit.RootLogBytes
                console = $console
            }
            $completedFaults++
            Write-Summary
        }
    }

    $result = 'pass'
}
catch {
    $result = 'fail'
    $failure = $_.Exception.Message
}
finally {
    foreach ($entry in @($activeProcesses.GetEnumerator())) {
        $process = $entry.Value
        try {
            $process.Refresh()
            if (-not $process.HasExited) {
                $process.Kill()
                $process.WaitForExit()
            }
        }
        catch {
            # The process may have exited between inspection and cleanup.
        }
    }
    $activeProcesses.Clear()
    $residual = @(Wait-ForA3sProcessesToExit)
    $finalInventory = $residual
    Write-JsonFile `
        -Path (Join-Path $evidenceDirectory 'inventory-final.json') `
        -Value @($finalInventory)
    if ($residual.Count -gt 0 -and $null -eq $failure) {
        $result = 'fail'
        $failure = 'The soak runner finished with residual A3S OCI processes.'
    }
    $verificationFailures = @(Get-VerificationFailures)
    if ($verificationFailures.Count -eq 0) {
        $verification = 'pass'
        Write-Utf8Text -Path (Join-Path $evidenceDirectory 'verify.out') `
            -Text "PASS`n"
    }
    else {
        $verification = 'fail'
        if ($result -eq 'pass') {
            $result = 'fail'
            $failure = 'Evidence verification failed: ' + (
                $verificationFailures -join '; '
            )
        }
        $verificationText = "FAIL`n" + (
            $verificationFailures | ForEach-Object { "- $_" }
        ) -join "`n"
        Write-Utf8Text -Path (Join-Path $evidenceDirectory 'verify.out') `
            -Text ($verificationText + "`n")
    }
    Write-Summary
}

Write-Host "Windows WHPX soak result: $result"
Write-Host "Evidence: $evidenceDirectory"
if ($failure) {
    throw $failure
}
