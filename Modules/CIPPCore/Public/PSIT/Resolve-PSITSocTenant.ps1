function Resolve-PSITSocTenant {
    <#
    .SYNOPSIS
        Turns the tenant name an external notification carries into a managed tenant.

    .DESCRIPTION
        The automation upstream of this webhook resolves a company in the PSA, not a Microsoft
        tenant: what reaches us is a display name, a domain, or something in between. CIPP
        partitions cases by defaultDomainName, so the two have to be reconciled here, where the
        tenant list already lives.

        Matching, in order, on a normalised form (case, accents and separators folded):
        1. exact defaultDomainName - the identifier itself, when the caller already knows it;
        2. exact displayName;
        3. exact initial domain or customerId;
        4. a single displayName starting with the name.

        A prefix match is only accepted when it is unambiguous. Two candidates mean the answer is
        unknown, and an unknown answer is reported as such rather than guessed: a case filed under
        the wrong client is worse than a case an analyst has to reassign, because nobody goes
        looking for it.

    .OUTPUTS
        An object carrying Tenant (the defaultDomainName, or 'unmapped') and Method (how it was
        matched, or why it was not), so the case says how it got its tenant.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Name,

        # The managed tenants, as Get-Tenants returns them. Injected so this stays testable.
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        $Tenants
    )

    $Unmapped = [pscustomobject]@{ Tenant = 'unmapped'; Method = 'no name supplied' }
    if ([string]::IsNullOrWhiteSpace($Name)) { return $Unmapped }

    $Normalise = {
        param($Value)
        if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
        # Accents folded, separators collapsed: 'Plein-Sud IT' and 'plein sud it' are one name.
        $Flat = [string]$Value
        $Flat = $Flat.Normalize([Text.NormalizationForm]::FormD) -replace '\p{Mn}', ''
        return ($Flat -replace '[_\-\.]+', ' ' -replace '\s+', ' ').Trim().ToLowerInvariant()
    }

    $Wanted = & $Normalise $Name
    if ([string]::IsNullOrWhiteSpace($Wanted)) { return $Unmapped }

    $Candidates = @($Tenants | Where-Object { $_ })

    foreach ($Property in @('defaultDomainName', 'displayName', 'initialDomainName', 'customerId')) {
        $Exact = @($Candidates | Where-Object { (& $Normalise $_.$Property) -eq $Wanted })
        if ($Exact.Count -eq 1) {
            return [pscustomobject]@{
                Tenant = [string]$Exact[0].defaultDomainName
                Method = "exact $Property"
            }
        }
        if ($Exact.Count -gt 1) {
            return [pscustomobject]@{ Tenant = 'unmapped'; Method = "ambiguous $Property" }
        }
    }

    $Starting = @($Candidates | Where-Object { (& $Normalise $_.displayName).StartsWith($Wanted) })
    if ($Starting.Count -eq 1) {
        return [pscustomobject]@{
            Tenant = [string]$Starting[0].defaultDomainName
            Method = 'displayName prefix'
        }
    }
    if ($Starting.Count -gt 1) {
        return [pscustomobject]@{ Tenant = 'unmapped'; Method = 'ambiguous displayName prefix' }
    }

    return [pscustomobject]@{ Tenant = 'unmapped'; Method = 'no match' }
}
