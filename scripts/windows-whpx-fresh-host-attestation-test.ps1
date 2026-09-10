# Fail-closed unit checks for WHPX fresh-host attestation resolution.
# Does not run the release matrix and does not promote readiness.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$lib = Join-Path $PSScriptRoot 'lib\windows-whpx-fresh-host-attestation.ps1'
. $lib

$work = Join-Path ([IO.Path]::GetTempPath()) ("a3s-oci-whpx-attestation-test-{0}" -f [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    # existing rejects attestation path
    $rejectedExistingPath = $false
    try {
        Resolve-WhpxFreshHostAttestation -HostClass existing -AttestationPath (Join-Path $work 'x.json') | Out-Null
    } catch {
        $rejectedExistingPath = $true
    }
    if (-not $rejectedExistingPath) {
        throw 'existing HostClass unexpectedly accepted an attestation path'
    }

    # existing without path yields nothing
    $existing = Resolve-WhpxFreshHostAttestation -HostClass existing -AttestationPath ''
    if ($null -ne $existing) {
        throw 'existing HostClass unexpectedly returned an attestation object'
    }

    # fresh without path fails
    $rejectedMissing = $false
    try {
        Resolve-WhpxFreshHostAttestation -HostClass fresh -AttestationPath '' | Out-Null
    } catch {
        $rejectedMissing = $true
    }
    if (-not $rejectedMissing) {
        throw 'fresh HostClass unexpectedly accepted a missing attestation'
    }

    # fresh with wrong schema fails
    $badPath = Join-Path $work 'bad.json'
    Set-Content -LiteralPath $badPath -Encoding utf8 -Value '{"schema_version":"wrong","operator_attests_fresh_provisioning":true,"provisioned_at_utc":"2026-09-07T00:00:00Z"}'
    $rejectedBadSchema = $false
    try {
        Resolve-WhpxFreshHostAttestation -HostClass fresh -AttestationPath $badPath | Out-Null
    } catch {
        $rejectedBadSchema = $true
    }
    if (-not $rejectedBadSchema) {
        throw 'fresh HostClass unexpectedly accepted a wrong schema'
    }

    # fresh rejects operator_attests_fresh_provisioning=false
    $falseAttestPath = Join-Path $work 'false-attest.json'
    Set-Content -LiteralPath $falseAttestPath -Encoding utf8 -Value '{"schema_version":"a3s.oci.windows-whpx-fresh-host-attestation.v1","operator_attests_fresh_provisioning":false,"provisioned_at_utc":"2026-09-07T00:00:00Z"}'
    $rejectedFalseAttest = $false
    try {
        Resolve-WhpxFreshHostAttestation -HostClass fresh -AttestationPath $falseAttestPath | Out-Null
    } catch {
        $rejectedFalseAttest = $true
    }
    if (-not $rejectedFalseAttest) {
        throw 'fresh HostClass unexpectedly accepted operator_attests_fresh_provisioning=false'
    }

    # fresh rejects missing provisioned_at_utc
    $missingUtcPath = Join-Path $work 'missing-utc.json'
    Set-Content -LiteralPath $missingUtcPath -Encoding utf8 -Value '{"schema_version":"a3s.oci.windows-whpx-fresh-host-attestation.v1","operator_attests_fresh_provisioning":true}'
    $rejectedMissingUtc = $false
    try {
        Resolve-WhpxFreshHostAttestation -HostClass fresh -AttestationPath $missingUtcPath | Out-Null
    } catch {
        $rejectedMissingUtc = $true
    }
    if (-not $rejectedMissingUtc) {
        throw 'fresh HostClass unexpectedly accepted a missing provisioned_at_utc'
    }

    # fresh rejects symlink attestation path when the host can create one
    $linkTarget = Join-Path $work 'link-target.json'
    Set-Content -LiteralPath $linkTarget -Encoding utf8 -Value '{"schema_version":"a3s.oci.windows-whpx-fresh-host-attestation.v1","operator_attests_fresh_provisioning":true,"provisioned_at_utc":"2026-09-07T00:00:00Z"}'
    $linkPath = Join-Path $work 'link.json'
    $symlinkCreated = $false
    try {
        New-Item -ItemType SymbolicLink -Path $linkPath -Target $linkTarget -ErrorAction Stop | Out-Null
        $symlinkCreated = $true
    } catch {
        # Developer Mode / elevation may be required; keep the other fail-closed cases mandatory.
    }
    if ($symlinkCreated) {
        $rejectedSymlink = $false
        try {
            Resolve-WhpxFreshHostAttestation -HostClass fresh -AttestationPath $linkPath | Out-Null
        } catch {
            $rejectedSymlink = $true
        }
        if (-not $rejectedSymlink) {
            throw 'fresh HostClass unexpectedly accepted a symlink attestation path'
        }
    }

    # fresh with valid attestation succeeds
    $goodPath = Join-Path $work 'good.json'
    Set-Content -LiteralPath $goodPath -Encoding utf8 -Value '{"schema_version":"a3s.oci.windows-whpx-fresh-host-attestation.v1","operator_attests_fresh_provisioning":true,"provisioned_at_utc":"2026-09-07T00:00:00Z","hostname":"whpx-release-01"}'
    $resolved = Resolve-WhpxFreshHostAttestation -HostClass fresh -AttestationPath $goodPath
    $resolvedPath = [IO.Path]::GetFullPath($goodPath)
    if ($resolved.schema_version -ne 'a3s.oci.windows-whpx-fresh-host-attestation.v1') {
        throw 'valid attestation returned unexpected schema_version'
    }
    if ($resolved.operator_attests_fresh_provisioning -ne $true) {
        throw 'valid attestation missing operator_attests_fresh_provisioning'
    }
    if ($resolved.path -ne $resolvedPath) {
        throw ("valid attestation path mismatch: {0} vs {1}" -f $resolved.path, $resolvedPath)
    }
    if ([string]$resolved.sha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'valid attestation missing sha256 digest'
    }
    if ($resolved.hostname -ne 'whpx-release-01') {
        throw 'valid attestation hostname mismatch'
    }

    Write-Output 'windows-whpx-fresh-host-attestation checks passed'
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
