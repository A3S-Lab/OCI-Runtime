# Fail-closed promotion policy for the WHPX release matrix.
# Fresh hosts may promote only with the full six-gate bound set and full soak profile.

$script:WhpxPromotionSoakIterations = 25
$script:WhpxPromotionOperationReopenCases = 180
$script:WhpxPromotionHandleReclamationIterations = 8
$script:WhpxPromotionSoakBreadth = [ordered]@{
    parallel_runs = 6
    multi_container_runs = 3
    lifecycle_faults = 3
    workload_cases = 5
    negative_cases = 10
    owner_kill_faults = 4
    duration_seconds = 0
}

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

function Test-WhpxSoakPromotionBreadth {
    param([Parameter(Mandatory)] [object]$SoakSummary)
    $required = $script:WhpxPromotionSoakBreadth
    $checks = @(
        @{ Name = 'requested_iterations'; Expected = $script:WhpxPromotionSoakIterations },
        @{ Name = 'completed_iterations'; Expected = $script:WhpxPromotionSoakIterations },
        @{ Name = 'requested_duration_seconds'; Expected = $required.duration_seconds },
        @{ Name = 'requested_parallel_runs'; Expected = $required.parallel_runs },
        @{ Name = 'completed_parallel_runs'; Expected = $required.parallel_runs },
        @{ Name = 'requested_multi_container_runs'; Expected = $required.multi_container_runs },
        @{ Name = 'completed_multi_container_runs'; Expected = $required.multi_container_runs },
        @{ Name = 'requested_lifecycle_faults'; Expected = $required.lifecycle_faults },
        @{ Name = 'completed_lifecycle_faults'; Expected = $required.lifecycle_faults },
        @{ Name = 'requested_workload_cases'; Expected = $required.workload_cases },
        @{ Name = 'completed_workload_cases'; Expected = $required.workload_cases },
        @{ Name = 'requested_negative_cases'; Expected = $required.negative_cases },
        @{ Name = 'completed_negative_cases'; Expected = $required.negative_cases },
        @{ Name = 'requested_owner_kill_faults'; Expected = $required.owner_kill_faults },
        @{ Name = 'completed_owner_kill_faults'; Expected = $required.owner_kill_faults }
    )
    foreach ($check in $checks) {
        $property = $SoakSummary.PSObject.Properties[$check.Name]
        if ($null -eq $property) {
            return $false
        }
        if ([int]$property.Value -ne [int]$check.Expected) {
            return $false
        }
    }
    return $true
}

function Assert-WhpxFreshHostSoakProfile {
    param(
        [Parameter(Mandatory)] [ValidateSet('existing', 'fresh')] [string]$HostClass,
        [Parameter(Mandatory)] [int]$RequestedIterations,
        [object]$SoakSummary = $null
    )
    if ($HostClass -ne 'fresh') {
        return
    }
    if ($RequestedIterations -ne $script:WhpxPromotionSoakIterations) {
        throw ("HostClass=fresh requires soak requested_iterations={0} (refusing reduced soak depth)." -f $script:WhpxPromotionSoakIterations)
    }
    if ($null -ne $SoakSummary -and -not (Test-WhpxSoakPromotionBreadth -SoakSummary $SoakSummary)) {
        throw 'HostClass=fresh requires the full default WHPX soak breadth (serial/parallel/multi-container/fault/workload/negative/owner-kill); refusing Skip* or zeroed profile knobs.'
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

function Assert-WhpxFreshHostHandleReclamationProfile {
    param(
        [Parameter(Mandatory)] [ValidateSet('existing', 'fresh')] [string]$HostClass,
        [Parameter(Mandatory)] [int]$RequestedIterations
    )
    if ($HostClass -eq 'fresh' -and
        $RequestedIterations -ne $script:WhpxPromotionHandleReclamationIterations) {
        throw ("HostClass=fresh requires handle-reclamation requested_iterations={0} (refusing thinned profile)." -f $script:WhpxPromotionHandleReclamationIterations)
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
        [int]$OperationReopenCaseCount = 0,
        [int]$HandleReclamationIterations = 0,
        [object]$SoakSummary = $null
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
    if ($null -eq $SoakSummary -or -not (Test-WhpxSoakPromotionBreadth -SoakSummary $SoakSummary)) {
        return $false
    }
    if ($OperationReopenCaseCount -ne $script:WhpxPromotionOperationReopenCases) {
        return $false
    }
    if ($HandleReclamationIterations -ne $script:WhpxPromotionHandleReclamationIterations) {
        return $false
    }
    return $true
}
