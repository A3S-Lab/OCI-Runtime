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
    throw 'The WHPX driver smoke must run on Windows.'
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
        "target\windows-whpx-driver-smoke\$runId"
}
$outputRoot = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $outputRoot) {
    throw "Refusing to reuse an existing WHPX driver smoke directory: $outputRoot"
}

$containerId = "whpx-driver-smoke-$PID"
$generation = 1
$runtimeRoot = Join-Path $outputRoot 'runtime'
$systemRoot = Join-Path $runtimeRoot 'system'
$runtimeShare = Join-Path $runtimeRoot "shares\$containerId\$generation"
$bundle = Join-Path $runtimeShare 'workloads\smoke'
$containerRootfs = Join-Path $bundle 'rootfs'
$reportPath = Join-Path $outputRoot 'report.json'
$stderrPath = Join-Path $outputRoot 'stderr.log'
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

function Get-A3sOciProcesses {
    @(
        Get-Process -ErrorAction SilentlyContinue |
            Where-Object {
                $_.ProcessName -in @('a3s-oci', 'a3s-oci-krun-shim')
            } |
            Select-Object ProcessName, Id, StartTime
    )
}

function Wait-ForA3sOciProcessesToExit {
    for ($attempt = 0; $attempt -lt 50; $attempt++) {
        $processes = @(Get-A3sOciProcesses)
        if ($processes.Count -eq 0) {
            return @()
        }
        Start-Sleep -Milliseconds 100
    }
    @(Get-A3sOciProcesses)
}

$preexisting = @(Get-A3sOciProcesses)
if ($preexisting.Count -gt 0) {
    $description = ($preexisting | ForEach-Object {
        '{0}:{1}' -f $_.ProcessName, $_.Id
    }) -join ', '
    throw "Refusing to start with active A3S OCI processes: $description"
}

New-Item -ItemType Directory -Path $systemRoot, $containerRootfs | Out-Null

if (-not $SkipBuild) {
    & cargo.exe zigbuild --manifest-path (Join-Path $repositoryRoot 'Cargo.toml') `
        -p a3s-oci-agent --release `
        --target x86_64-unknown-linux-musl
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to build the static Linux guest agent.'
    }
    & cargo.exe build --manifest-path (Join-Path $repositoryRoot 'Cargo.toml') `
        -p a3s-oci-cli -p a3s-oci-krun
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to build the Windows qualification binaries.'
    }
}
foreach ($path in @($cli, $shim, $krunDll, $agent)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required WHPX driver smoke binary is missing: $path"
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

$arguments = @(
    'whpx-driver-smoke',
    '--shim', $shim,
    '--runtime-root', $runtimeRoot,
    '--vm-rootfs', $systemRoot,
    '--bundle', $bundle,
    '--container-id', $containerId,
    '--generation', $generation.ToString()
)
$stderrLines = @()
$stdoutLines = @(& $cli @arguments 2>&1 | ForEach-Object {
    if ($_ -is [Management.Automation.ErrorRecord]) {
        $script:stderrLines += $_.ToString()
    }
    else {
        $_.ToString()
    }
})
$exitCode = $LASTEXITCODE
$stdout = $stdoutLines -join [Environment]::NewLine
$stderr = $stderrLines -join [Environment]::NewLine
Write-Utf8Text -Path $reportPath -Text $stdout
Write-Utf8Text -Path $stderrPath -Text $stderr

$report = $null
try {
    $report = $stdout | ConvertFrom-Json
}
catch {
    throw "WHPX driver smoke emitted invalid JSON: $($_.Exception.Message)"
}
if ($exitCode -ne 0 -or $report.status -ne 'available') {
    throw "WHPX driver smoke failed with exit code $exitCode; see $reportPath"
}
if ($report.schema_version -ne 'a3s.oci.whpx-driver-smoke.v1') {
    throw "Unexpected WHPX driver smoke schema: $($report.schema_version)"
}

$residual = @(Wait-ForA3sOciProcessesToExit)
if ($residual.Count -gt 0) {
    $description = ($residual | ForEach-Object {
        '{0}:{1}' -f $_.ProcessName, $_.Id
    }) -join ', '
    throw "WHPX driver smoke leaked host processes: $description"
}

$commit = (& git -C $repositoryRoot rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) {
    throw 'Unable to resolve the repository commit.'
}
$summary = [ordered]@{
    schema_version = 'a3s.oci.whpx-driver-smoke-run.v1'
    status = 'available'
    started_at_utc = $startedAt.ToString('o')
    completed_at_utc = [DateTime]::UtcNow.ToString('o')
    commit = $commit
    worktree_status = @(& git -C $repositoryRoot status --porcelain)
    rootfs_archive = $rootfsArchive
    rootfs_sha256 = $rootfsSha256
    agent_sha256 = (
        Get-FileHash -LiteralPath $agent -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    shim_sha256 = (
        Get-FileHash -LiteralPath $shim -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    krun_dll_sha256 = (
        Get-FileHash -LiteralPath $krunDll -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    container_id = $containerId
    generation = $generation
    report = $report
}
Write-Utf8Text -Path $summaryPath -Text (
    ConvertTo-Json -InputObject $summary -Depth 20
)

Write-Output "WHPX driver smoke passed: $reportPath"
Get-Content -LiteralPath $reportPath
