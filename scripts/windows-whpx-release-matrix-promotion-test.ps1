# Fail-closed unit checks for WHPX release-matrix promotion policy.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'lib\windows-whpx-release-matrix-promotion.ps1')

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

$rejectedFreshSkipReopen = $false
try {
    Assert-WhpxFreshHostSkipPolicy -HostClass fresh -SkipOperationReopen
} catch {
    $rejectedFreshSkipReopen = $true
}
if (-not $rejectedFreshSkipReopen) {
    throw 'fresh HostClass unexpectedly allowed -SkipOperationReopen'
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
Assert-WhpxFreshHostSoakProfile -HostClass fresh -RequestedIterations 25

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

if (Get-WhpxPromotesReadiness -HostClass existing -HasFreshHostAttestation $true -GateCount 6 -SoakRequestedIterations 25 -SoakCompletedIterations 25 -OperationReopenCaseCount 180) {
    throw 'existing HostClass unexpectedly promoted readiness'
}
if (-not (Get-WhpxPromotesReadiness -HostClass fresh -HasFreshHostAttestation $true -GateCount 6 -SoakRequestedIterations 25 -SoakCompletedIterations 25 -OperationReopenCaseCount 180)) {
    throw 'fresh HostClass with full gates unexpectedly failed to promote'
}
if (Get-WhpxPromotesReadiness -HostClass fresh -HasFreshHostAttestation $true -SkipSoak -GateCount 5) {
    throw 'fresh HostClass with -SkipSoak unexpectedly promoted readiness'
}
if (Get-WhpxPromotesReadiness -HostClass fresh -HasFreshHostAttestation $true -SkipOperationReopen -GateCount 5) {
    throw 'fresh HostClass with -SkipOperationReopen unexpectedly promoted readiness'
}
if (Get-WhpxPromotesReadiness -HostClass fresh -HasFreshHostAttestation $true -GateCount 5 -SoakRequestedIterations 25 -SoakCompletedIterations 25 -OperationReopenCaseCount 180) {
    throw 'fresh HostClass with incomplete gate_count unexpectedly promoted readiness'
}
if (Get-WhpxPromotesReadiness -HostClass fresh -HasFreshHostAttestation $true -GateCount 6 -SoakRequestedIterations 1 -SoakCompletedIterations 1 -OperationReopenCaseCount 180) {
    throw 'fresh HostClass with reduced soak depth unexpectedly promoted readiness'
}
if (Get-WhpxPromotesReadiness -HostClass fresh -HasFreshHostAttestation $true -GateCount 6 -SoakRequestedIterations 25 -SoakCompletedIterations 25 -OperationReopenCaseCount 20) {
    throw 'fresh HostClass with thinned operation-reopen unexpectedly promoted readiness'
}
if (Get-WhpxPromotesReadiness -HostClass fresh -HasFreshHostAttestation $false -GateCount 6 -SoakRequestedIterations 25 -SoakCompletedIterations 25 -OperationReopenCaseCount 180) {
    throw 'fresh HostClass without attestation unexpectedly promoted readiness'
}

Write-Output 'windows-whpx-release-matrix-promotion checks passed'
