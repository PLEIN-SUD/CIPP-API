# Pester tests for the licence gate on SOC actions.
#
# The distinction this pins: "not licensed" and "could not check" must never resolve to the same
# answer. Hiding an action because a cache call failed is how an analyst learns the tool is
# missing something it actually has.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Get-PSITSocCapabilities.ps1')

    function Get-CIPPTenantCapabilities { param($TenantFilter, $APIName, $Headers) }

    $script:ActionOf = {
        param($Capabilities, $Name)
        ($Capabilities.Actions | Where-Object { $_.Action -eq $Name })
    }
}

Describe 'Get-PSITSocCapabilities' {
    It 'allows the purge on a tenant with Defender for Office 365 Plan 2' {
        $Result = Get-PSITSocCapabilities -TenantFilter 'contoso.test' -Capabilities ([pscustomobject]@{
                THREAT_INTELLIGENCE = $true
                ATP_ENTERPRISE      = $true
            })

        $Purge = & $script:ActionOf $Result 'mail-remediate'
        $Purge.State | Should -Be 'available'
    }

    It 'refuses the purge on Plan 1, and says where to do it instead' {
        $Result = Get-PSITSocCapabilities -TenantFilter 'contoso.test' -Capabilities ([pscustomobject]@{
                ATP_ENTERPRISE      = $true
                THREAT_INTELLIGENCE = $false
            })

        $Purge = & $script:ActionOf $Result 'mail-remediate'
        $Purge.State | Should -Be 'unlicensed'
        # Where to do it instead: the answer has to be actionable, not only negative.
        $Purge.Fallback | Should -Be 'threat-explorer'

        # Plan 1 still has MDO alerts to adopt.
        (& $script:ActionOf $Result 'mdo-alerts').State | Should -Be 'available'
    }

    It 'says a tenant with no Defender for Office has no MDO alerts to adopt' {
        $Result = Get-PSITSocCapabilities -TenantFilter 'contoso.test' -Capabilities ([pscustomobject]@{})
        (& $script:ActionOf $Result 'mdo-alerts').State | Should -Be 'unlicensed'
        (& $script:ActionOf $Result 'mail-remediate').State | Should -Be 'unlicensed'
    }

    It 'answers unknown, never unlicensed, when the licences cannot be read' {
        # An action hidden because a cache call failed is an action nobody knows they still have.
        Mock -CommandName Get-CIPPTenantCapabilities -MockWith { throw 'Graph unavailable' }

        $Result = Get-PSITSocCapabilities -TenantFilter 'contoso.test'
        foreach ($Action in $Result.Actions) {
            $Action.State | Should -Be 'unknown'
        }
    }

    It 'names the plan an action needs, so the answer is actionable' {
        $Result = Get-PSITSocCapabilities -TenantFilter 'contoso.test' -Capabilities ([pscustomobject]@{})
        $Purge = & $script:ActionOf $Result 'mail-remediate'
        $Purge.RequiredSku | Should -Be 'THREAT_INTELLIGENCE'
        $Purge.SkuName | Should -Be 'Defender for Office 365 Plan 2'
    }
}
