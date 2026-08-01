[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$RootfsArchive,
    [string]$OutputDirectory = '',
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'The WHPX recovery smoke must run on Windows.'
}

$expectedRootfsSha256 = '4b4daa9fe2fc696c4919c4412a4c3d3e770d8fb70292a004a2c72f5096175282'
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$rootfsArchive = (Resolve-Path -LiteralPath $RootfsArchive -ErrorAction Stop).Path
$fixtureConfig = Join-Path $repositoryRoot 'fixtures\utility-vm\config.windows.json'
$cli = Join-Path $repositoryRoot 'target\debug\a3s-oci.exe'
$shim = Join-Path $repositoryRoot 'target\debug\a3s-oci-krun-shim.exe'
$krunDll = Join-Path $repositoryRoot 'target\debug\krun.dll'
$agent = Join-Path $repositoryRoot `
    'target\x86_64-unknown-linux-musl\release\a3s-oci-agent'
$tar = (Get-Command tar.exe -ErrorAction Stop).Source
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

$archiveItem = Get-Item -LiteralPath $rootfsArchive -Force
if ($archiveItem.PSIsContainer -or $archiveItem.Length -le 0) {
    throw "Rootfs archive must be a non-empty regular file: $rootfsArchive"
}
if ($archiveItem.PSObject.Properties.Name -contains 'LinkType' -and $archiveItem.LinkType) {
    throw "Rootfs archive must not be a link: $rootfsArchive"
}
$rootfsSha256 = (
    Get-FileHash -LiteralPath $rootfsArchive -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($rootfsSha256 -ne $expectedRootfsSha256) {
    throw "Rootfs SHA-256 mismatch: expected $expectedRootfsSha256, found $rootfsSha256"
}
if (-not (Test-Path -LiteralPath $fixtureConfig -PathType Leaf)) {
    throw "Windows OCI fixture is missing: $fixtureConfig"
}

$runId = '{0}-{1}' -f (
    Get-Date
).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'), $PID
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repositoryRoot `
        "target\windows-whpx-recovery-smoke\$runId"
}
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $outputRoot) {
    throw "Refusing to reuse an existing WHPX recovery smoke directory: $outputRoot"
}

$containerId = "whpx-recovery-smoke-$PID"
$expectedGeneration = 1
$runtimeRoot = Join-Path $outputRoot 'runtime'
$systemRoot = Join-Path $runtimeRoot 'system'
$stateRoot = Join-Path $runtimeRoot 'state'
$runtimeShare = Join-Path $runtimeRoot `
    "shares\$containerId\$expectedGeneration"
$bundle = Join-Path $runtimeShare 'workloads\smoke'
$containerRootfs = Join-Path $bundle 'rootfs'
$readyPath = Join-Path $outputRoot 'owner-ready.json'
$ownerStdoutPath = Join-Path $outputRoot 'owner.stdout.log'
$ownerStderrPath = Join-Path $outputRoot 'owner.stderr.log'
$reportPath = Join-Path $outputRoot 'report.json'
$resumeStderrPath = Join-Path $outputRoot 'resume.stderr.log'
$summaryPath = Join-Path $outputRoot 'summary.json'
$startedAt = [DateTime]::UtcNow

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

function Join-QuotedNativeArguments {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    @($Arguments | ForEach-Object {
        if ($_.Contains('"')) {
            throw "Native argument contains an unsupported quote: $_"
        }
        '"{0}"' -f $_
    }) -join ' '
}

function Get-A3sOciProcesses {
    @(
        Get-Process -ErrorAction SilentlyContinue |
            Where-Object {
                $_.ProcessName -in @('a3s-oci', 'a3s-oci-krun-shim')
            } |
            Select-Object ProcessName, Id, StartTime
    )
}

function Wait-ForProcessExit {
    param(
        [Parameter(Mandatory)]
        [int]$ProcessId,
        [int]$Attempts = 200
    )

    for ($attempt = 0; $attempt -lt $Attempts; $attempt++) {
        if ($null -eq (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)) {
            return $true
        }
        Start-Sleep -Milliseconds 100
    }
    return $false
}

$preexisting = @(Get-A3sOciProcesses)
if ($preexisting.Count -gt 0) {
    $description = ($preexisting | ForEach-Object {
        '{0}:{1}' -f $_.ProcessName, $_.Id
    }) -join ', '
    throw "Refusing to start with active A3S OCI processes: $description"
}

New-Item -ItemType Directory -Path `
    $systemRoot, $stateRoot, $containerRootfs | Out-Null

if (-not $SkipBuild) {
    & cargo.exe zigbuild --manifest-path (Join-Path $repositoryRoot 'Cargo.toml') `
        -p a3s-oci-agent --release `
        --jobs 1 `
        --target x86_64-unknown-linux-musl
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to build the static Linux guest agent.'
    }
    & cargo.exe build --manifest-path (Join-Path $repositoryRoot 'Cargo.toml') `
        -p a3s-oci-cli -p a3s-oci-krun --jobs 1
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to build the Windows recovery qualification binaries.'
    }
}
foreach ($path in @($cli, $shim, $krunDll, $agent)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required WHPX recovery smoke binary is missing: $path"
    }
}

& $tar -xf $rootfsArchive -C $systemRoot
if ($LASTEXITCODE -ne 0) {
    throw 'Failed to extract the WHPX guest system root.'
}
& $tar -xf $rootfsArchive -C $containerRootfs
if ($LASTEXITCODE -ne 0) {
    throw 'Failed to extract the WHPX container rootfs.'
}
New-Item -ItemType Directory -Path (
    Join-Path $systemRoot 'run\a3s-oci-runtime'
) -Force | Out-Null
New-Item -ItemType Directory -Path (
    Join-Path $systemRoot 'usr\bin'
) -Force | Out-Null
Copy-Item -LiteralPath $agent `
    -Destination (Join-Path $systemRoot 'usr\bin\a3s-oci-agent') -Force
Copy-Item -LiteralPath $fixtureConfig `
    -Destination (Join-Path $bundle 'config.json') -Force

$ownerArguments = @(
    'whpx-recovery-owner',
    '--shim', $shim,
    '--runtime-root', $runtimeRoot,
    '--vm-rootfs', $systemRoot,
    '--state-root', $stateRoot,
    '--bundle', $bundle,
    '--container-id', $containerId,
    '--ready-file', $readyPath
)
$owner = $null
$ownerShimProcessId = $null
$ownerExitCode = $null
$ownerKilledAt = $null
$report = $null
$ready = $null

try {
    $owner = Start-Process -FilePath $cli `
        -ArgumentList (Join-QuotedNativeArguments -Arguments $ownerArguments) `
        -WorkingDirectory $repositoryRoot `
        -RedirectStandardOutput $ownerStdoutPath `
        -RedirectStandardError $ownerStderrPath `
        -WindowStyle Hidden `
        -PassThru

    for ($attempt = 0; $attempt -lt 600; $attempt++) {
        if (Test-Path -LiteralPath $readyPath -PathType Leaf) {
            $ready = Get-Content -LiteralPath $readyPath -Raw | ConvertFrom-Json
            break
        }
        if ($owner.HasExited) {
            $ownerExitCode = $owner.ExitCode
            $stderr = if (Test-Path -LiteralPath $ownerStderrPath) {
                Get-Content -LiteralPath $ownerStderrPath -Raw
            }
            else {
                ''
            }
            throw "WHPX recovery owner exited before readiness ($ownerExitCode): $stderr"
        }
        Start-Sleep -Milliseconds 100
        $owner.Refresh()
    }
    if ($null -eq $ready) {
        throw "Timed out waiting for WHPX recovery owner readiness: $readyPath"
    }
    if ($ready.schema_version -ne 'a3s.oci.whpx-recovery-owner-ready.v1' -or
        $ready.status -ne 'available' -or
        $ready.target.id -ne $containerId -or
        [uint64]$ready.target.generation -ne $expectedGeneration -or
        [uint32]$ready.owner_pid -ne [uint32]$owner.Id -or
        -not $ready.running_observed -or
        -not $ready.marker_observed -or
        -not $ready.qualification_override_scoped) {
        throw "WHPX recovery owner emitted invalid readiness: $readyPath"
    }

    $shimProcesses = @(
        Get-Process -Name 'a3s-oci-krun-shim' -ErrorAction SilentlyContinue
    )
    if ($shimProcesses.Count -ne 1) {
        throw "Expected exactly one owner-bound WHPX shim, found $($shimProcesses.Count)"
    }
    $ownerShimProcessId = [int]$shimProcesses[0].Id

    Stop-Process -Id $owner.Id -Force
    if (-not $owner.WaitForExit(5000)) {
        throw "WHPX recovery owner did not exit after exact forced termination: $($owner.Id)"
    }
    $ownerExitCode = $owner.ExitCode
    $ownerKilledAt = [DateTime]::UtcNow

    $resumeArguments = @(
        'whpx-recovery-resume',
        '--shim', $shim,
        '--runtime-root', $runtimeRoot,
        '--vm-rootfs', $systemRoot,
        '--state-root', $stateRoot,
        '--bundle', $bundle,
        '--container-id', $containerId,
        '--generation', $expectedGeneration.ToString()
    )
    $stderrLines = @()
    $stdoutLines = @(& $cli @resumeArguments 2>&1 | ForEach-Object {
        if ($_ -is [Management.Automation.ErrorRecord]) {
            $script:stderrLines += $_.ToString()
        }
        else {
            $_.ToString()
        }
    })
    $resumeExitCode = $LASTEXITCODE
    $stdout = $stdoutLines -join [Environment]::NewLine
    $resumeStderr = $stderrLines -join [Environment]::NewLine
    Write-Utf8Text -Path $reportPath -Text $stdout
    Write-Utf8Text -Path $resumeStderrPath -Text $resumeStderr
    try {
        $report = $stdout | ConvertFrom-Json
    }
    catch {
        throw "WHPX recovery resume emitted invalid JSON: $($_.Exception.Message)"
    }
    if ($resumeExitCode -ne 0 -or $report.status -ne 'available') {
        throw "WHPX recovery resume failed with exit code $resumeExitCode; see $reportPath"
    }
    if ($report.schema_version -ne 'a3s.oci.whpx-recovery-smoke.v1') {
        throw "Unexpected WHPX recovery smoke schema: $($report.schema_version)"
    }
    if (-not (Wait-ForProcessExit -ProcessId $ownerShimProcessId)) {
        throw "Owner-bound WHPX shim survived recovery cleanup: $ownerShimProcessId"
    }
}
finally {
    if ($null -ne $owner -and -not $owner.HasExited) {
        Stop-Process -Id $owner.Id -Force -ErrorAction SilentlyContinue
        [void]$owner.WaitForExit(5000)
    }
    if ($null -ne $ownerShimProcessId) {
        $remainingShim = Get-Process -Id $ownerShimProcessId -ErrorAction SilentlyContinue
        if ($null -ne $remainingShim -and
            $remainingShim.ProcessName -eq 'a3s-oci-krun-shim') {
            Stop-Process -Id $ownerShimProcessId -Force -ErrorAction SilentlyContinue
        }
    }
}

$residual = @(Get-A3sOciProcesses)
if ($residual.Count -gt 0) {
    $description = ($residual | ForEach-Object {
        '{0}:{1}' -f $_.ProcessName, $_.Id
    }) -join ', '
    throw "WHPX recovery smoke leaked host processes: $description"
}

$commit = (& git -C $repositoryRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to resolve the repository commit.'
}
$summary = [ordered]@{
    schema_version = 'a3s.oci.whpx-recovery-smoke-run.v1'
    status = 'available'
    started_at_utc = $startedAt.ToString('o')
    owner_killed_at_utc = $ownerKilledAt.ToString('o')
    completed_at_utc = [DateTime]::UtcNow.ToString('o')
    commit = $commit
    worktree_status = @(& git -C $repositoryRoot status --porcelain)
    rootfs_archive = $rootfsArchive
    rootfs_sha256 = $rootfsSha256
    agent_sha256 = (
        Get-FileHash -LiteralPath $agent -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    cli_sha256 = (
        Get-FileHash -LiteralPath $cli -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    shim_sha256 = (
        Get-FileHash -LiteralPath $shim -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    krun_dll_sha256 = (
        Get-FileHash -LiteralPath $krunDll -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    owner_process_id = $owner.Id
    owner_exit_code = $ownerExitCode
    owner_shim_process_id = $ownerShimProcessId
    ready = $ready
    report = $report
}
Write-Utf8Text -Path $summaryPath -Text (
    ConvertTo-Json -InputObject $summary -Depth 20
)

Write-Output "WHPX recovery smoke passed: $reportPath"
Get-Content -LiteralPath $reportPath
