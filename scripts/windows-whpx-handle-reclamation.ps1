[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$RootfsArchive,
    [Parameter(Mandatory)]
    [string]$SystemImageManifest,
    [ValidateRange(1, 64)]
    [int]$Iterations = 8,
    [ValidateRange(30, 3600)]
    [int]$TimeoutSeconds = 900,
    [string]$OutputDirectory = '',
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'The WHPX handle-reclamation gate must run on Windows.'
}

$expectedRootfsSha256 = '4b4daa9fe2fc696c4919c4412a4c3d3e770d8fb70292a004a2c72f5096175282'
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$rootfsArchive = (Resolve-Path -LiteralPath $RootfsArchive -ErrorAction Stop).Path
$systemImageManifest = (
    Resolve-Path -LiteralPath $SystemImageManifest -ErrorAction Stop
).Path
$shim = Join-Path $repositoryRoot 'target\debug\a3s-oci-krun-shim.exe'
$krunDll = Join-Path $repositoryRoot 'target\debug\krun.dll'
$firmwareDll = Join-Path $repositoryRoot 'target\debug\libkrunfw.dll'
$tar = (Get-Command tar.exe -ErrorAction Stop).Source
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Assert-PlainFile {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Description
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -le 0) {
        throw "$Description must be a non-empty regular file: $Path"
    }
    if ($item.PSObject.Properties.Name -contains 'LinkType' -and $item.LinkType) {
        throw "$Description must not be a link: $Path"
    }
    $item
}

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

    Write-Utf8Text -Path $Path -Text (
        ConvertTo-Json -InputObject $Value -Depth 12
    )
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

$archiveItem = Assert-PlainFile -Path $rootfsArchive `
    -Description 'Rootfs archive'
$rootfsSha256 = (
    Get-FileHash -LiteralPath $rootfsArchive -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($rootfsSha256 -ne $expectedRootfsSha256) {
    throw "Rootfs SHA-256 mismatch: expected $expectedRootfsSha256, found $rootfsSha256"
}

$manifestItem = Assert-PlainFile -Path $systemImageManifest `
    -Description 'System-image manifest'
$systemImage = Get-Content -LiteralPath $systemImageManifest -Raw |
    ConvertFrom-Json
if ($systemImage.schema_version -ne 'a3s.oci.windows-system-image.v1' -or
    $systemImage.architecture -ne 'x86_64' -or
    $systemImage.image.name -ne 'a3s-oci-system.ext4') {
    throw "Unexpected Windows system-image manifest: $systemImageManifest"
}
$systemImagePath = Join-Path $manifestItem.DirectoryName $systemImage.image.name
$systemImageItem = Assert-PlainFile -Path $systemImagePath `
    -Description 'Windows system image'
$systemImageSha256 = (
    Get-FileHash -LiteralPath $systemImagePath -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($systemImageSha256 -ne $systemImage.image.sha256 -or
    $systemImageItem.Length -ne [uint64]$systemImage.image.size) {
    throw "Windows system image does not match its manifest: $systemImagePath"
}
$systemImageManifestSha256 = (
    Get-FileHash -LiteralPath $systemImageManifest -Algorithm SHA256
).Hash.ToLowerInvariant()

$runId = '{0}-{1}' -f (
    Get-Date
).ToUniversalTime().ToString('yyyyMMddTHHmmssZ'), $PID
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repositoryRoot `
        "target\windows-whpx-handle-reclamation\$runId"
}
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $outputRoot) {
    throw "Refusing to reuse an existing WHPX handle-reclamation directory: $outputRoot"
}

$rootfs = Join-Path $outputRoot 'rootfs'
$runtimeShare = Join-Path $outputRoot 'runtime-share'
$consoleDirectory = Join-Path $outputRoot 'consoles'
$reportPath = Join-Path $outputRoot 'report.json'
$stderrPath = Join-Path $outputRoot 'stderr.log'
$summaryPath = Join-Path $outputRoot 'summary.json'
New-Item -ItemType Directory -Path `
    $rootfs, $runtimeShare, $consoleDirectory | Out-Null

& $tar -xf $rootfsArchive -C $rootfs
if ($LASTEXITCODE -ne 0) {
    throw 'Failed to extract the fixed portable OCI rootfs.'
}
if (-not (Test-Path -LiteralPath (Join-Path $rootfs 'bin\sh') -PathType Leaf)) {
    throw 'The extracted portable OCI rootfs does not contain /bin/sh.'
}

if (-not $SkipBuild) {
    & cargo.exe build --manifest-path (Join-Path $repositoryRoot 'Cargo.toml') `
        -p a3s-oci-krun --jobs 1
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to build the Windows libkrun shim.'
    }
}
foreach ($path in @($shim, $krunDll, $firmwareDll)) {
    Assert-PlainFile -Path $path -Description 'WHPX qualification binary' |
        Out-Null
}
$krunDllSha256 = (
    Get-FileHash -LiteralPath $krunDll -Algorithm SHA256
).Hash.ToLowerInvariant()
$firmwareDllSha256 = (
    Get-FileHash -LiteralPath $firmwareDll -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($systemImage.runtime.krun_dll.sha256 -ne $krunDllSha256 -or
    $systemImage.runtime.firmware.sha256 -ne $firmwareDllSha256) {
    throw 'The adjacent Windows runtime DLLs do not match the system-image manifest.'
}

$preexisting = @(Get-A3sOciProcesses)
if ($preexisting.Count -gt 0) {
    $description = ($preexisting | ForEach-Object {
        '{0}:{1}' -f $_.ProcessName, $_.Id
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
$startedAt = [DateTime]::UtcNow
$failures = New-Object 'System.Collections.Generic.List[string]'
$report = $null
$shimExitCode = $null

try {
    $arguments = @(
        'whpx-handle-reclamation-smoke',
        '--rootfs', $rootfs,
        '--system-image-manifest', $systemImageManifest,
        '--runtime-share', $runtimeShare,
        '--console-directory', $consoleDirectory,
        '--iterations', $Iterations.ToString()
    )
    $process = Start-Process -FilePath $shim `
        -ArgumentList (Join-QuotedNativeArguments -Arguments $arguments) `
        -RedirectStandardOutput $reportPath `
        -RedirectStandardError $stderrPath `
        -PassThru
    if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
        Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        $process.WaitForExit()
        $failures.Add(
            "WHPX reclamation shim exceeded the $TimeoutSeconds-second timeout"
        )
    }
    else {
        $shimExitCode = $process.ExitCode
    }

    try {
        $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    }
    catch {
        $failures.Add("shim report is not valid JSON: $($_.Exception.Message)")
    }

    if ($null -ne $report) {
        if ($report.schema_version -ne
            'a3s.oci.krun-whpx-handle-reclamation-smoke.v1') {
            $failures.Add("unexpected report schema: $($report.schema_version)")
        }
        if ($report.platform -ne 'windows' -or $report.status -ne 'available') {
            $failures.Add(
                "WHPX reclamation status is $($report.platform)/$($report.status)"
            )
        }
        if ($report.requested_iterations -ne $Iterations -or
            $report.completed_iterations -ne $Iterations -or
            @($report.samples).Count -ne $Iterations) {
            $failures.Add(
                "completed $($report.completed_iterations) of $Iterations measured iterations"
            )
        }
        if (-not $report.runtime_bundle_loaded -or
            -not $report.runtime_share_restored) {
            $failures.Add('runtime bundle or runtime-share cleanup evidence is incomplete')
        }
        if ($null -eq $report.warmup -or
            $report.warmup.guest_exit_code -ne 0 -or
            -not $report.warmup.marker_verified -or
            -not $report.warmup.marker_removed -or
            -not $report.warmup.console_created) {
            $failures.Add('the warmup VM did not complete its fixed workload and cleanup')
        }
        $failedSamples = @($report.samples | Where-Object {
            $_.guest_exit_code -ne 0 -or
            -not $_.marker_verified -or
            -not $_.marker_removed -or
            -not $_.console_created -or
            $null -ne $_.reason
        })
        if ($failedSamples.Count -gt 0) {
            $failures.Add("$($failedSamples.Count) measured VM samples failed")
        }
        if ($null -eq $report.baseline_handle_count -or
            $null -eq $report.final_handle_count -or
            $report.final_handle_count -gt (
                $report.baseline_handle_count + $report.allowed_final_handle_delta
            )) {
            $failures.Add(
                "process handles did not return to the warmed baseline: " +
                "baseline=$($report.baseline_handle_count), " +
                "final=$($report.final_handle_count), " +
                "allowed_delta=$($report.allowed_final_handle_delta)"
            )
        }
        if ($report.windows_boot_assets.manifest_sha256 -ne
                $systemImageManifestSha256 -or
            $report.windows_boot_assets.system_image_sha256 -ne
                $systemImageSha256 -or
            $report.windows_boot_assets.krun_dll_sha256 -ne $krunDllSha256 -or
            $report.windows_boot_assets.firmware_sha256 -ne $firmwareDllSha256) {
            $failures.Add('retained boot-asset evidence does not match the fixed inputs')
        }
        if ($null -ne $report.reason) {
            $failures.Add("shim reported failure: $($report.reason)")
        }
    }

    if ($shimExitCode -ne 0) {
        $failures.Add("WHPX reclamation shim exited with status $shimExitCode")
    }
    if ($worktreeStatus.Count -gt 0) {
        $failures.Add('the qualification checkout is not clean')
    }
    $remainingRuntimeEntries = @(
        Get-ChildItem -LiteralPath $runtimeShare -Force -ErrorAction Stop
    )
    if ($remainingRuntimeEntries.Count -gt 0) {
        $failures.Add(
            "$($remainingRuntimeEntries.Count) runtime-share entries remained after the gate"
        )
    }
    $expectedConsoleCount = $Iterations + 1
    $consoleFiles = @(
        Get-ChildItem -LiteralPath $consoleDirectory -File -Force
    )
    if ($consoleFiles.Count -ne $expectedConsoleCount -or
        @($consoleFiles | Where-Object { $_.Length -le 0 }).Count -gt 0) {
        $failures.Add(
            "expected $expectedConsoleCount non-empty console logs, found $($consoleFiles.Count)"
        )
    }
}
catch {
    $failures.Add($_.Exception.Message)
}

Start-Sleep -Milliseconds 250
$remainingProcesses = @(Get-A3sOciProcesses)
if ($remainingProcesses.Count -gt 0) {
    $description = ($remainingProcesses | ForEach-Object {
        '{0}:{1}' -f $_.ProcessName, $_.Id
    }) -join ', '
    $failures.Add("A3S OCI processes remained after the gate: $description")
}

$finishedAt = [DateTime]::UtcNow
$summary = [ordered]@{
    schema_version = 'a3s.oci.windows-whpx-handle-reclamation-run.v1'
    result = if ($failures.Count -eq 0) { 'pass' } else { 'fail' }
    commit = $commit
    worktree_dirty = $worktreeStatus.Count -gt 0
    worktree_status = @($worktreeStatus)
    started_at = $startedAt.ToString('o')
    finished_at = $finishedAt.ToString('o')
    duration_seconds = [Math]::Round(($finishedAt - $startedAt).TotalSeconds, 3)
    rootfs_archive = $rootfsArchive
    rootfs_archive_size = [uint64]$archiveItem.Length
    rootfs_archive_sha256 = $rootfsSha256
    system_image_manifest = $systemImageManifest
    system_image_manifest_sha256 = $systemImageManifestSha256
    system_image = $systemImagePath
    system_image_sha256 = $systemImageSha256
    shim = $shim
    shim_sha256 = (
        Get-FileHash -LiteralPath $shim -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    krun_dll_sha256 = $krunDllSha256
    firmware_dll_sha256 = $firmwareDllSha256
    requested_iterations = $Iterations
    timeout_seconds = $TimeoutSeconds
    shim_exit_code = $shimExitCode
    remaining_processes = $remainingProcesses
    failures = @($failures)
    report = $report
}
Write-JsonFile -Path $summaryPath -Value $summary

Write-Output "WHPX handle-reclamation evidence: $outputRoot"
Write-Output "Summary: $summaryPath"
if ($failures.Count -gt 0) {
    throw "WHPX handle-reclamation qualification failed: $($failures -join '; ')"
}
