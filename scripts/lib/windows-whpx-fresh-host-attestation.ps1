# Fail-closed WHPX fresh-host attestation resolution.
# Dot-source from release-matrix and unit tests. Does not promote readiness by itself.

function Get-WhpxFreshHostOptionalProperty {
    param(
        [Parameter(Mandatory)] [object]$Object,
        [Parameter(Mandatory)] [string]$Name
    )
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Get-WhpxFreshHostSha256 {
    param([Parameter(Mandatory)] [string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-WhpxFreshHostRegularFile {
    param([Parameter(Mandatory)] [string]$Path, [Parameter(Mandatory)] [string]$Label)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or $item.Length -le 0) {
        throw "$Label must be a non-empty regular file: $Path"
    }
    if ($item.PSObject.Properties.Name -contains 'LinkType' -and
        $item.LinkType -eq 'SymbolicLink') {
        throw "$Label must not be a link: $Path"
    }
    return $item
}

function Resolve-WhpxFreshHostAttestation {
    param(
        [Parameter(Mandatory)] [ValidateSet('existing', 'fresh')] [string]$HostClass,
        [string]$AttestationPath
    )
    $hasPath = -not [string]::IsNullOrWhiteSpace($AttestationPath)

    if ($HostClass -eq 'existing') {
        if ($hasPath) {
            throw 'FreshHostAttestation is only valid with -HostClass fresh.'
        }
        # Explicit empty result: `return $null` can still surface prior pipeline
        # output under StrictMode callers; emit nothing and stop.
        return
    }

    if (-not $hasPath) {
        throw 'HostClass=fresh requires -FreshHostAttestation pointing to a single-use operator attestation JSON.'
    }
    $resolved = (Resolve-Path -LiteralPath $AttestationPath -ErrorAction Stop).Path
    Assert-WhpxFreshHostRegularFile -Path $resolved -Label 'Fresh-host attestation' | Out-Null
    $attestation = Get-Content -LiteralPath $resolved -Raw | ConvertFrom-Json
    if ($attestation.schema_version -ne 'a3s.oci.windows-whpx-fresh-host-attestation.v1') {
        throw "Unexpected fresh-host attestation schema: $($attestation.schema_version)"
    }
    if ($attestation.operator_attests_fresh_provisioning -ne $true) {
        throw 'Fresh-host attestation must set operator_attests_fresh_provisioning=true.'
    }
    $provisionedAt = Get-WhpxFreshHostOptionalProperty -Object $attestation -Name 'provisioned_at_utc'
    if ([string]::IsNullOrWhiteSpace([string]$provisionedAt)) {
        throw 'Fresh-host attestation must include provisioned_at_utc.'
    }
    $hostname = Get-WhpxFreshHostOptionalProperty -Object $attestation -Name 'hostname'
    return [ordered]@{
        path = $resolved
        sha256 = (Get-WhpxFreshHostSha256 -Path $resolved)
        schema_version = [string]$attestation.schema_version
        operator_attests_fresh_provisioning = $true
        provisioned_at_utc = [string]$provisionedAt
        hostname = if ($null -eq $hostname) { $null } else { [string]$hostname }
    }
}
