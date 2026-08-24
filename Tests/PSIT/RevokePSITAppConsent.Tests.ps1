# Pester tests for the OAuth consent revocation: the containment gesture of SOC triage type 6.
#
# The properties pinned here are the ones an analyst relies on mid-incident: the principal is
# disabled FIRST (the door closes before the sweep), every grant and assignment is deleted, a
# failed step never stops the following ones, and the principal itself survives - disabled -
# because deleting it would destroy the evidence.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Revoke-PSITAppConsent.ps1')

    function New-GraphGetRequest { param($uri, $tenantid) }
    function New-GraphPOSTRequest { param($uri, $type, $tenantid, $body) }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $headers, $LogData) }

    $script:Sp = [pscustomobject]@{
        id             = 'sp-object-id'
        appId          = 'ff8d92dc-3d82-41d6-bcbd-b9174d163620'
        displayName    = 'Suspicious Mail App'
        accountEnabled = $true
    }
}

Describe 'Revoke-PSITAppConsent' {
    BeforeEach {
        $script:Writes = [System.Collections.Generic.List[object]]::new()
        Mock -CommandName Write-LogMessage -MockWith { }
        # Branch order matters: the appRoleAssignments uri also contains 'servicePrincipals/<id>',
        # so the specific patterns are tested before the generic one.
        Mock -CommandName New-GraphGetRequest -MockWith {
            if ($uri -like '*oauth2PermissionGrants*') {
                return @([pscustomobject]@{ id = 'grant-1' }, [pscustomobject]@{ id = 'grant-2' })
            }
            if ($uri -like '*appRoleAssignments*') {
                return @([pscustomobject]@{ id = 'assignment-1' })
            }
            if ($uri -like "*servicePrincipals?*appId eq*") { return @($script:Sp) }
            if ($uri -like '*servicePrincipals/sp-object-id*') { return $script:Sp }
            return $null
        }
        Mock -CommandName New-GraphPOSTRequest -MockWith {
            $script:Writes.Add([pscustomobject]@{ Type = $type; Uri = $uri; Body = [string]$body })
        }
    }

    It 'disables the principal, then deletes every grant and assignment' {
        $Result = Revoke-PSITAppConsent -TenantFilter 'contoso.test' -ServicePrincipalId 'sp-object-id' -Analyst 'a'

        $Patch = @($script:Writes | Where-Object { $_.Type -eq 'PATCH' })
        $Patch.Count | Should -Be 1
        $Patch[0].Uri | Should -BeLike '*servicePrincipals/sp-object-id'
        $Patch[0].Body | Should -BeLike '*"accountEnabled":false*'

        @($script:Writes | Where-Object { $_.Type -eq 'DELETE' -and $_.Uri -like '*oauth2PermissionGrants/grant-*' }).Count | Should -Be 2
        @($script:Writes | Where-Object { $_.Type -eq 'DELETE' -and $_.Uri -like '*appRoleAssignments/assignment-1' }).Count | Should -Be 1
        # The principal is never deleted: disabled, kept as evidence.
        @($script:Writes | Where-Object { $_.Type -eq 'DELETE' -and $_.Uri -like '*servicePrincipals/sp-object-id' }).Count | Should -Be 0
        @($Result.Results | Where-Object { $_.state -eq 'success' }).Count | Should -Be 3
    }

    It 'resolves the principal from an appId when that is all the case carries' {
        $Result = Revoke-PSITAppConsent -TenantFilter 'contoso.test' -AppId $script:Sp.appId -Analyst 'a'

        $Result.ServicePrincipalId | Should -Be 'sp-object-id'
        $Result.DisplayName | Should -Be 'Suspicious Mail App'
    }

    It 'a failed disable does not stop the grant sweep: partial revocation beats none' {
        Mock -CommandName New-GraphPOSTRequest -MockWith {
            if ($type -eq 'PATCH') { throw 'Insufficient privileges' }
        }

        $Result = Revoke-PSITAppConsent -TenantFilter 'contoso.test' -ServicePrincipalId 'sp-object-id' -Analyst 'a'

        @($Result.Results | Where-Object { $_.state -eq 'error' }).Count | Should -Be 1
        # The two other steps still ran and reported success.
        @($Result.Results | Where-Object { $_.state -eq 'success' }).Count | Should -Be 2
    }

    It 'refuses to run without any identifier, and throws on an unknown principal' {
        { Revoke-PSITAppConsent -TenantFilter 'contoso.test' -Analyst 'a' } |
            Should -Throw '*ServicePrincipalId or AppId*'

        Mock -CommandName New-GraphGetRequest -MockWith { $null }
        { Revoke-PSITAppConsent -TenantFilter 'contoso.test' -AppId 'unknown' -Analyst 'a' } |
            Should -Throw '*No service principal found*'
    }
}
