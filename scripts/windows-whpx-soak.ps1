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
    [ValidateRange(0, 1000)]
    [int]$ParallelWaves = 3,
    [ValidateRange(1, 16)]
    [int]$Parallelism = 2,
    [int[]]$OwnerKillDelayMilliseconds = @(0, 250, 1000, 2500),
    [ValidateRange(1, 3600)]
    [int]$CommandTimeoutSeconds = 120,
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
$fixtureConfig = Join-Path $PSScriptRoot 'fixtures\windows-soak\config.json'
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
$completedIterations = 0
$completedParallelRuns = 0
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

    Write-Utf8Text -Path $Path -Text ($Value | ConvertTo-Json -Depth 20)
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

    $scriptSource = Join-Path $Bundle 'volumes\init scripts\init.sh'
    $stateDirectory = Join-Path $Bundle 'volumes\state'
    $configSource = Join-Path $Bundle 'volumes\config\init.conf'
    New-Item -ItemType Directory -Path $stateDirectory -Force | Out-Null
    New-Item -ItemType Directory -Path (Split-Path -Parent $configSource) `
        -Force | Out-Null
    Copy-WorkloadAsset -Name $Asset -Destination $scriptSource
    Write-Utf8Text -Path $configSource -Text 'profile=windows-whpx'

    $scriptTarget = Join-Path $ContainerRootfs 'opt\a3s\init.sh'
    $stateTarget = Join-Path $ContainerRootfs 'var\lib\a3s-init'
    $configTarget = Join-Path $ContainerRootfs 'etc\a3s-init.conf'
    $workTarget = Join-Path $ContainerRootfs 'work'
    New-Item -ItemType Directory -Path $stateTarget, $workTarget -Force | Out-Null
    New-Item -ItemType Directory -Path (Split-Path -Parent $scriptTarget) `
        -Force | Out-Null
    Write-Utf8Text -Path $scriptTarget -Text ''
    Write-Utf8Text -Path $configTarget -Text ''

    $Config.mounts = @($Config.mounts) + @(
        (New-OciMount -Destination '/opt/a3s/init.sh' -Type 'none' `
            -Source 'volumes/init scripts/init.sh' `
            -Options @('bind', 'ro', 'nosuid', 'nodev', 'noexec')),
        (New-OciMount -Destination '/var/lib/a3s-init' -Type 'none' `
            -Source 'volumes/state' -Options @('bind', 'rw', 'nosuid', 'nodev')),
        (New-OciMount -Destination '/etc/a3s-init.conf' -Type 'none' `
            -Source 'volumes/config/init.conf' `
            -Options @('bind', 'ro', 'nosuid', 'nodev', 'noexec'))
    )
    $Config.process.args = @('/bin/sh', '/opt/a3s/init.sh')
    $Config.process.cwd = '/work'
    $Config.process.user | Add-Member -NotePropertyName umask `
        -NotePropertyValue 23 -Force
    $Config.process.env = @($Config.process.env) + @(
        "A3S_INIT_SCENARIO=$Scenario"
    )
    if ($DelayBeforeReady) {
        $Config.process.env += 'A3S_INIT_DELAY_SECONDS=1'
    }

    [pscustomobject]@{
        Evidence = Join-Path $stateDirectory 'lifecycle.log'
        Source = $scriptSource
        ReadOnlySource = $configSource
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
            'joined-pid',
            'joined-network',
            'mounts-without-namespace',
            'capabilities',
            'net-devices',
            'hooks',
            'missing-mount-source',
            'missing-mount-target',
            'readonly-root',
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
    $scenarioMetadata = [pscustomobject]@{
        Evidence = $null
        Source = $null
        ReadOnlySource = $null
        Scratch = $null
        RoundTrip = $null
    }
    switch ($Variant) {
        'joined-pid' {
            $pidNamespace = @(
                $config.linux.namespaces | Where-Object { $_.type -eq 'pid' }
            )
            if ($pidNamespace.Count -ne 1) {
                throw 'The positive fixture must contain exactly one PID namespace.'
            }
            $pidNamespace[0] | Add-Member -NotePropertyName path `
                -NotePropertyValue '/proc/1/ns/pid'
        }
        'joined-network' {
            $networkNamespace = @(
                $config.linux.namespaces |
                    Where-Object { $_.type -eq 'network' }
            )
            if ($networkNamespace.Count -ne 1) {
                throw 'The positive fixture must contain exactly one network namespace.'
            }
            $networkNamespace[0] | Add-Member -NotePropertyName path `
                -NotePropertyValue '/proc/1/ns/net'
        }
        'mounts-without-namespace' {
            $config.linux.namespaces = @(
                $config.linux.namespaces | Where-Object { $_.type -ne 'mount' }
            )
        }
        'capabilities' {
            $capabilities = [pscustomobject][ordered]@{
                bounding = @()
                effective = @()
                inheritable = @()
                permitted = @()
                ambient = @()
            }
            $config.process | Add-Member -NotePropertyName capabilities `
                -NotePropertyValue $capabilities
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
        'hooks' {
            $hooks = [pscustomobject][ordered]@{
                createRuntime = @(
                    [pscustomobject][ordered]@{
                        path = '/bin/true'
                        args = @('/bin/true')
                    }
                )
            }
            $config | Add-Member -NotePropertyName hooks -NotePropertyValue $hooks
        }
        'missing-mount-source' {
            $target = Join-Path $containerRootfs 'mnt\missing-source'
            New-Item -ItemType Directory -Path $target -Force | Out-Null
            $config.mounts = @($config.mounts) + @(
                (New-OciMount -Destination '/mnt/missing-source' -Type 'none' `
                    -Source 'volumes/does-not-exist' -Options @('bind', 'ro'))
            )
        }
        'missing-mount-target' {
            $source = Join-Path $bundle 'volumes\present'
            New-Item -ItemType Directory -Path $source -Force | Out-Null
            $config.mounts = @($config.mounts) + @(
                (New-OciMount -Destination '/a3s-missing/target' -Type 'none' `
                    -Source 'volumes/present' -Options @('bind', 'ro'))
            )
        }
        'readonly-root' {
            $config.root.readonly = $true
        }
        'network-isolated' {
            $config.linux.namespaces = @(
                $config.linux.namespaces | Where-Object { $_.type -ne 'pid' }
            )
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
                    Where-Object { $_.type -notin @('network', 'pid') }
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
            $treeSource = Join-Path $bundle 'volumes\tree'
            New-Item -ItemType Directory -Path $rwSource, $readOnlySource, `
                (Join-Path $treeSource 'proc') -Force | Out-Null
            $sentinel = Join-Path $readOnlySource 'sentinel.txt'
            Write-Utf8Text -Path $sentinel -Text 'read-only-volume-v1'

            $scriptTarget = Join-Path $containerRootfs 'opt\a3s\storage-matrix.sh'
            Copy-WorkloadAsset -Name 'storage-matrix.sh' -Destination $scriptTarget
            $rwTarget = Join-Path $containerRootfs 'mnt\rw'
            $readOnlyTarget = Join-Path $containerRootfs 'mnt\readonly'
            $treeTarget = Join-Path $containerRootfs 'mnt\tree'
            $scratchTarget = Join-Path $containerRootfs 'scratch'
            New-Item -ItemType Directory -Path $rwTarget, $readOnlyTarget, `
                $treeTarget, $scratchTarget -Force | Out-Null

            $config.mounts = @($config.mounts) + @(
                (New-OciMount -Destination '/mnt/rw' -Type 'none' `
                    -Source 'volumes/rw' `
                    -Options @('bind', 'rw', 'nosuid', 'nodev', 'noexec')),
                (New-OciMount -Destination '/mnt/readonly' -Type 'none' `
                    -Source 'volumes/readonly' `
                    -Options @('bind', 'ro', 'nosuid', 'nodev', 'noexec')),
                (New-OciMount -Destination '/mnt/tree' -Type 'none' `
                    -Source 'volumes/tree' -Options @('rbind', 'rprivate')),
                (New-OciMount -Destination '/mnt/tree/proc' -Type 'proc' `
                    -Source 'proc' -Options @('nosuid', 'noexec', 'nodev')),
                (New-OciMount -Destination '/scratch' -Type 'tmpfs' `
                    -Source 'tmpfs' `
                    -Options @('nosuid', 'nodev', 'noexec', 'size=65536', 'mode=1770'))
            )
            $config.process.args = @('/bin/sh', '/opt/a3s/storage-matrix.sh')
            $scenarioMetadata.Evidence = Join-Path $rwSource 'lifecycle.log'
            $scenarioMetadata.ReadOnlySource = $sentinel
            $scenarioMetadata.Scratch = $scratchTarget
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
    $configPath = Join-Path $bundle 'config.json'
    Write-JsonFile -Path $configPath -Value $config
    if ($Variant -eq 'storage-matrix') {
        $configBytes = (Get-Item -LiteralPath $configPath).Length
        if ($configBytes -le 4096) {
            throw (
                'The storage matrix must keep its create request above the ' +
                "4 KiB WHPX transport boundary; config.json is $configBytes bytes."
            )
        }
    }

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
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -in @('a3s-oci.exe', 'a3s-oci-krun-shim.exe')
            } |
            Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine
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
    if ($Result.Report.schema_version -ne 'a3s.oci.oci-vm-smoke.v2' -or
        $Result.Report.status -ne 'available') {
        throw "$Label did not return an available v2 report"
    }
    $trueFields = @(
        'bundle_loaded',
        'create_returned_created',
        'create_replayed',
        'marker_absent_after_create',
        'start_released',
        'running_observed',
        'kill_delivered',
        'kill_replayed',
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
        $Result.Report.bridge.selected_protocol -ne 1) {
        throw "$Label did not retain a successful authenticated bridge"
    }
    $operations = @($Result.Report.bridge.advertised_operations) -join ','
    if ($operations -ne 'create,state,start,kill,delete') {
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
            Get-CimInstance Win32_Process `
                -Filter "ParentProcessId = $OwnerProcessId" `
                -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -eq 'a3s-oci-krun-shim.exe' }
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

    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" `
        -ErrorAction SilentlyContinue
    if ($null -eq $process) {
        return $false
    }
    [StringComparer]::OrdinalIgnoreCase.Equals($process.ExecutablePath, $script:shim)
}

function Write-Summary {
    $finishedAt = [DateTime]::UtcNow
    $ownerKillDelays = New-Object 'System.Collections.Generic.List[int]'
    if (-not $SkipFaultInjection) {
        foreach ($delay in $OwnerKillDelayMilliseconds) {
            $ownerKillDelays.Add($delay)
        }
    }
    $summary = [ordered]@{
        schema = 'a3s.oci.windows-whpx-soak.v1'
        run_id = $script:runId
        result = $script:result
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
        completed_parallel_runs = $script:completedParallelRuns
        requested_workload_cases = if ($SkipWorkloadCases) {
            0
        }
        else {
            5 * $WorkloadIterations
        }
        completed_workload_cases = $script:completedWorkloadCases
        requested_negative_cases = if ($SkipNegativeCases) { 0 } else { 9 }
        owner_kill_delays_ms = $ownerKillDelays
        completed_owner_kill_faults = $script:completedFaults
        completed_negative_cases = $script:completedNegatives
        command_timeout_seconds = $CommandTimeoutSeconds
        serial_root_log_growth_bytes = (
            $script:serialFinalLogBytes - $script:serialInitialLogBytes
        )
        failure = $script:failure
        samples = $script:samples
    }
    Write-JsonFile -Path (Join-Path $script:evidenceDirectory 'summary.json') `
        -Value $summary
}

try {
    $preexisting = @(Get-A3sProcesses)
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

    $operatingSystem = Get-CimInstance Win32_OperatingSystem
    $computerSystem = Get-CimInstance Win32_ComputerSystem
    Write-JsonFile -Path (Join-Path $evidenceDirectory 'host.json') -Value ([ordered]@{
        caption = $operatingSystem.Caption
        version = $operatingSystem.Version
        build_number = $operatingSystem.BuildNumber
        architecture = $operatingSystem.OSArchitecture
        logical_processors = $computerSystem.NumberOfLogicalProcessors
        total_visible_memory_kib = $operatingSystem.TotalVisibleMemorySize
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
    $context = Start-CapturedProcess -FilePath $shim -Arguments @('context-smoke')
    $context = Complete-CapturedProcess -Running $context
    Save-ProcessEvidence -Label 'context-smoke' -Completed $context
    $contextReport = $context.Stdout | ConvertFrom-Json
    if ($context.ExitCode -ne 0 -or $contextReport.status -ne 'available') {
        throw 'The libkrun context smoke is unavailable.'
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
            'network-isolated',
            'network-inherited',
            'storage-matrix',
            'init-script'
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
                            'init_net=',
                            'interfaces=',
                            'phase=term'
                        )
                }
                'storage-matrix' {
                    Assert-TextEvidence -Label $label `
                        -Path $fixture.Scenario.Evidence -RequiredFragments @(
                            'phase=ready',
                            'readonly=verified',
                            'nested_proc=verified',
                            'tmpfs=verified',
                            'noexec=verified',
                            'rw_round_trip=verified',
                            'phase=term'
                        )
                    $sentinel = Get-Content `
                        -LiteralPath $fixture.Scenario.ReadOnlySource -Raw
                    if ($sentinel -ne 'read-only-volume-v1') {
                        throw "$label mutated the read-only bind source"
                    }
                    $roundTrip = Get-Content `
                        -LiteralPath $fixture.Scenario.RoundTrip -Raw
                    if ($roundTrip -ne "rw-round-trip-v1`n") {
                        throw "$label did not persist the RW bind round trip"
                    }
                    $scratchEntries = @(
                        Get-ChildItem -LiteralPath $fixture.Scenario.Scratch `
                            -Force -ErrorAction SilentlyContinue
                    )
                    if ($scratchEntries.Count -ne 0) {
                        throw "$label persisted files that belonged to tmpfs"
                    }
                }
                'init-script' {
                    Assert-TextEvidence -Label $label `
                        -Path $fixture.Scenario.Evidence -RequiredFragments @(
                            'phase=begin',
                            'scenario=volume-init',
                            'cwd=/work',
                            'umask=',
                            'config=verified',
                            'phase=ready',
                            'phase=term'
                        )
                    $configSource = Get-Content `
                        -LiteralPath $fixture.Scenario.ReadOnlySource -Raw
                    if ($configSource -ne 'profile=windows-whpx') {
                        throw "$label mutated the read-only init configuration"
                    }
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
                        throw "$label mutated the read-only init script source"
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
                Variant = 'joined-pid'
                Layer = 'guest'
                Code = 'Unsupported'
                Expected = 'linux.namespaces[5].path'
            },
            [pscustomobject]@{
                Variant = 'mounts-without-namespace'
                Layer = 'guest'
                Code = 'Unsupported'
                Expected = 'mounts'
            },
            [pscustomobject]@{
                Variant = 'capabilities'
                Layer = 'guest'
                Code = 'Unsupported'
                Expected = 'process.capabilities'
            },
            [pscustomobject]@{
                Variant = 'joined-network'
                Layer = 'guest'
                Code = 'Unsupported'
                Expected = 'linux.namespaces[3].path'
            },
            [pscustomobject]@{
                Variant = 'net-devices'
                Layer = 'guest'
                Code = 'Unsupported'
                Expected = 'linux.netDevices'
            },
            [pscustomobject]@{
                Variant = 'hooks'
                Layer = 'guest'
                Code = 'Unsupported'
                Expected = 'config.hooks'
            },
            [pscustomobject]@{
                Variant = 'missing-mount-source'
                Layer = 'guest'
                Code = 'InvalidArgument'
                Expected = 'mounts[1].source'
            },
            [pscustomobject]@{
                Variant = 'missing-mount-target'
                Layer = 'guest'
                Code = 'InvalidArgument'
                Expected = 'mounts[1].destination'
            },
            [pscustomobject]@{
                Variant = 'readonly-root'
                Layer = 'host'
                Code = 'HostPreflight'
                Expected = 'writable normalized relative root.path'
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
            if ($case.Layer -eq 'guest') {
                if (-not ([string]$run.Report.reason).Contains($case.Code)) {
                    throw "$label did not retain typed $($case.Code) evidence"
                }
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
    if ($residual.Count -gt 0 -and $null -eq $failure) {
        $result = 'fail'
        $failure = 'The soak runner finished with residual A3S OCI processes.'
    }
    Write-Summary
}

Write-Host "Windows WHPX soak result: $result"
Write-Host "Evidence: $evidenceDirectory"
if ($failure) {
    throw $failure
}
