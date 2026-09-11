# Fail-closed promotion policy for the WHPX release matrix.
# Fresh hosts may promote only with the full six-gate bound set and full soak depth.

$script:WhpxPromotionSoakIterations = 25
$script:WhpxPromotionOperationReopenCases = 180

function Assert-WhpxFreshHostSkipPolicy {
    param(
        [Parameter(Mandatory)] [ValidateSet('existing', 'fresh')] [string]$HostClass,
        [switch]$SkipSoak,
        [switch]$SkipOperationReopen
    )
    if ($HostClass -eq 'fresh' -and ($SkipSoak -or $SkipOperationReopen)) {
        throw 'HostClass=fresh refuses -SkipSoak / -SkipOperationReopen (full six-gate matrix is required to promote readiness).'
    }
}

function Assert-WhpxFreshHostSoakProfile {
    param(
        [Parameter(Mandatory)] [ValidateSet('existing', 'fresh')] [string]$HostClass,
        [Parameter(Mandatory)] [int]$RequestedIterations
    )
    if ($HostClass -eq 'fresh' -and
        $RequestedIterations -ne $script:WhpxPromotionSoakIterations) {
        throw ("HostClass=fresh requires soak requested_iterations={0} (refusing reduced soak depth)." -f $script:WhpxPromotionSoakIterations)
    }
}

function Assert-WhpxFreshHostOperationReopenProfile {
    param(
        [Parameter(Mandatory)] [ValidateSet('existing', 'fresh')] [string]$HostClass,
        [Parameter(Mandatory)] [int]$CaseCount
    )
    if ($HostClass -eq 'fresh' -and
        $CaseCount -ne $script:WhpxPromotionOperationReopenCases) {
        throw ("HostClass=fresh requires operation-reopen case_count={0} (refusing thinned reopen profile)." -f $script:WhpxPromotionOperationReopenCases)
    }
}

function Get-WhpxPromotesReadiness {
    param(
        [Parameter(Mandatory)] [ValidateSet('existing', 'fresh')] [string]$HostClass,
        [Parameter(Mandatory)] [bool]$HasFreshHostAttestation,
        [switch]$SkipSoak,
        [switch]$SkipOperationReopen,
        [Parameter(Mandatory)] [int]$GateCount,
        [int]$SoakRequestedIterations = 0,
        [int]$SoakCompletedIterations = 0,
        [int]$OperationReopenCaseCount = 0
    )
    if ($HostClass -ne 'fresh') {
        return $false
    }
    if (-not $HasFreshHostAttestation) {
        return $false
    }
    if ($SkipSoak -or $SkipOperationReopen) {
        return $false
    }
    if ($GateCount -ne 6) {
        return $false
    }
    if ($SoakRequestedIterations -ne $script:WhpxPromotionSoakIterations -or
        $SoakCompletedIterations -ne $script:WhpxPromotionSoakIterations) {
        return $false
    }
    if ($OperationReopenCaseCount -ne $script:WhpxPromotionOperationReopenCases) {
        return $false
    }
    return $true
}
