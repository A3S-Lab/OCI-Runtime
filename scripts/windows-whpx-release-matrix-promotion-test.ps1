# Fail-closed unit checks for WHPX release-matrix promotion policy.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'lib\windows-whpx-release-matrix-promotion.ps1')

function New-FullSoakSummary {
    return [pscustomobject]@{
        requested_iterations = 25
        completed_iterations = 25
        requested_duration_seconds = 0
        requested_parallel_runs = 6
        completed_parallel_runs = 6
        requested_multi_container_runs = 3
        completed_multi_container_runs = 3
        requested_lifecycle_faults = 3
        completed_lifecycle_faults = 3
        requested_workload_cases = 5
        completed_workload_cases = 5
        requested_negative_cases = 10
        completed_negative_cases = 10
        requested_owner_kill_faults = 4
        completed_owner_kill_faults = 4
    }
}

Assert-WhpxFreshHostSkipPolicy -HostClass existing -SkipSoak -SkipOperationReopen

$rejectedFreshSkip = $false
try {
    Assert-WhpxFreshHostSkipPolicy -HostClass fresh -SkipSoak
} catch {
    $rejectedFreshSkip = $true
}
if (-not $rejectedFreshSkip) {
    throw 'fresh HostClass unexpectedly allowed -SkipSoak'
}

Assert-WhpxFreshHostSkipPolicy -HostClass fresh

Assert-WhpxFreshHostSoakProfile -HostClass existing -RequestedIterations 1
$rejectedReducedSoak = $false
try {
    Assert-WhpxFreshHostSoakProfile -HostClass fresh -RequestedIterations 1
} catch {
    $rejectedReducedSoak = $true
}
if (-not $rejectedReducedSoak) {
    throw 'fresh HostClass unexpectedly allowed reduced soak depth'
}

$fullSoak = New-FullSoakSummary
Assert-WhpxFreshHostSoakProfile -HostClass fresh -RequestedIterations 25 -SoakSummary $fullSoak

$thinnedParallel = New-FullSoakSummary
$thinnedParallel.requested_parallel_runs = 0
$thinnedParallel.completed_parallel_runs = 0
$rejectedThinnedBreadth = $false
try {
    Assert-WhpxFreshHostSoakProfile -HostClass fresh -RequestedIterations 25 -SoakSummary $thinnedParallel
} catch {
    $rejectedThinnedBreadth = $true
}
if (-not $rejectedThinnedBreadth) {
    throw 'fresh HostClass unexpectedly allowed SkipParallel-style soak breadth'
}

Assert-WhpxFreshHostOperationReopenProfile -HostClass existing -CaseCount 1
$rejectedThinnedReopen = $false
try {
    Assert-WhpxFreshHostOperationReopenProfile -HostClass fresh -CaseCount 1
} catch {
    $rejectedThinnedReopen = $true
}
if (-not $rejectedThinnedReopen) {
    throw 'fresh HostClass unexpectedly allowed thinned operation-reopen profile'
}
Assert-WhpxFreshHostOperationReopenProfile -HostClass fresh -CaseCount 180

Assert-WhpxFreshHostHandleReclamationProfile -HostClass existing -RequestedIterations 1
$rejectedThinnedHandle = $false
try {
    Assert-WhpxFreshHostHandleReclamationProfile -HostClass fresh -RequestedIterations 1
} catch {
    $rejectedThinnedHandle = $true
}
if (-not $rejectedThinnedHandle) {
    throw 'fresh HostClass unexpectedly allowed thinned handle-reclamation profile'
}
Assert-WhpxFreshHostHandleReclamationProfile -HostClass fresh -RequestedIterations 8

if (Get-WhpxPromotesReadiness -HostClass existing -HasFreshHostAttestation $true -GateCount 6 -SoakRequestedIterations 25 -SoakCompletedIterations 25 -OperationReopenCaseCount 180 -HandleReclamationIterations 8 -SoakSummary $fullSoak) {
    throw 'existing HostClass unexpectedly promoted readiness'
}
if (-not (Get-WhpxPromotesReadiness -HostClass fresh -HasFreshHostAttestation $true -GateCount 6 -SoakRequestedIterations 25 -SoakCompletedIterations 25 -OperationReopenCaseCount 180 -HandleReclamationIterations 8 -SoakSummary $fullSoak)) {
    throw 'fresh HostClass with full gates unexpectedly failed to promote'
}
if (Get-WhpxPromotesReadiness -HostClass fresh -HasFreshHostAttestation $true -GateCount 6 -SoakRequestedIterations 25 -SoakCompletedIterations 25 -OperationReopenCaseCount 180 -HandleReclamationIterations 8 -SoakSummary $thinnedParallel) {
    throw 'fresh HostClass with thinned soak breadth unexpectedly promoted readiness'
}
if (Get-WhpxPromotesReadiness -HostClass fresh -HasFreshHostAttestation $true -GateCount 6 -SoakRequestedIterations 25 -SoakCompletedIterations 25 -OperationReopenCaseCount 180 -HandleReclamationIterations 1 -SoakSummary $fullSoak) {
    throw 'fresh HostClass with thinned handle-reclamation unexpectedly promoted readiness'
}
if (Get-WhpxPromotesReadiness -HostClass fresh -HasFreshHostAttestation $true -SkipSoak -GateCount 5) {
    throw 'fresh HostClass with -SkipSoak unexpectedly promoted readiness'
}
if (Get-WhpxPromotesReadiness -HostClass fresh -HasFreshHostAttestation $false -GateCount 6 -SoakRequestedIterations 25 -SoakCompletedIterations 25 -OperationReopenCaseCount 180 -HandleReclamationIterations 8 -SoakSummary $fullSoak) {
    throw 'fresh HostClass without attestation unexpectedly promoted readiness'
}

Write-Output 'windows-whpx-release-matrix-promotion checks passed'
