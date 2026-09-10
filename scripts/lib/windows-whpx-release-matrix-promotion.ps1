# Fail-closed promotion policy for the WHPX release matrix.
# Fresh hosts may promote only with the full six-gate bound set.

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

function Get-WhpxPromotesReadiness {
    param(
        [Parameter(Mandatory)] [ValidateSet('existing', 'fresh')] [string]$HostClass,
        [Parameter(Mandatory)] [bool]$HasFreshHostAttestation,
        [switch]$SkipSoak,
        [switch]$SkipOperationReopen,
        [Parameter(Mandatory)] [int]$GateCount
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
    return $true
}
