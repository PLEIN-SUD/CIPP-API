function Get-PSITSocCapabilities {
    <#
    .SYNOPSIS
        Which SOC actions this tenant is licensed for, and why when it is not.

    .DESCRIPTION
        Some containment actions need a licence the tenant may not have. Offering a button that
        answers "Invalid subscription" teaches an analyst to distrust the buttons; hiding it with
        no explanation teaches them the tool is incomplete. So each action reports three things:
        whether it is available, the plan it needs, and the sentence to show when it is not.

        Built on Get-CIPPTenantCapabilities, which reads subscribedSkus and caches for a day. The
        service plan names are the ones upstream already checks (ATP_ENTERPRISE for Defender for
        Office 365 Plan 1, THREAT_INTELLIGENCE for Plan 2).

        A capability lookup that fails answers 'unknown' rather than false: "we could not check"
        and "you do not have it" are different facts, and an action hidden because a cache call
        failed is an action nobody knows they still have.

        The wording stays in the frontend: this module is English like the rest of the API, and
        the SOC section is the only French surface. Each action therefore carries a state and the
        plan it needs, and the panel writes the sentence.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,

        # Injected for tests; fetched when absent.
        [AllowNull()]
        $Capabilities
    )

    $Unknown = $false
    if ($null -eq $Capabilities) {
        try {
            $Capabilities = Get-CIPPTenantCapabilities -TenantFilter $TenantFilter
        } catch {
            $Unknown = $true
            $Capabilities = [pscustomobject]@{}
        }
    }

    $Has = {
        param($Plan)
        if ($Unknown) { return $null }
        return $Capabilities.$Plan -eq $true
    }

    $MdoPlan2 = & $Has 'THREAT_INTELLIGENCE'
    $MdoPlan1 = & $Has 'ATP_ENTERPRISE'
    # Not ($MdoPlan1 -or $MdoPlan2): $null -or $null is $false in PowerShell, which would turn
    # "we could not check" into "not licensed" - the one confusion this module exists to prevent.
    $MdoAny = if ($Unknown) { $null } else { ($MdoPlan1 -eq $true) -or ($MdoPlan2 -eq $true) }

    $State = {
        param($Value)
        if ($null -eq $Value) { return 'unknown' }
        if ($Value) { return 'available' }
        return 'unlicensed'
    }

    return [PSCustomObject]@{
        TenantFilter = $TenantFilter
        Actions      = @(
            [PSCustomObject]@{
                Action      = 'mail-remediate'
                State       = & $State $MdoPlan2
                RequiredSku = 'THREAT_INTELLIGENCE'
                SkuName     = 'Defender for Office 365 Plan 2'
                # Where the analyst does it instead, when the tenant cannot: named here because
                # the answer has to be actionable, not only negative.
                Fallback    = 'threat-explorer'
            }
            [PSCustomObject]@{
                Action      = 'mdo-alerts'
                State       = & $State $MdoAny
                RequiredSku = 'ATP_ENTERPRISE'
                SkuName     = 'Defender for Office 365 Plan 1 or 2'
                Fallback    = ''
            }
        )
    }
}
