# Pester tests for Get-PSITUserAdminStatus.
#
# The badge exists because an administrator changes how everything else reads: a consent granted
# by one binds the whole tenant, and a compromise on one is not the same incident. What is pinned
# here is that the reading never overstates and never quietly understates - an account eligible
# through PIM is flagged, roles held through a group are counted, and a half-answered question
# says so instead of returning 'not an administrator'.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Get-PSITUserAdminStatus.ps1' -File |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $FunctionPath) { throw 'Could not locate Get-PSITUserAdminStatus.ps1 under Modules/' }

    function New-GraphGetRequest { param($uri, $tenantid, $scope, $AsApp, $NoAuthCheck) }

    . $FunctionPath
}

Describe 'Get-PSITUserAdminStatus' {
    BeforeEach {
        Mock -CommandName New-GraphGetRequest -MockWith {
            param($uri)
            if ($uri -match 'transitiveMemberOf') {
                @([PSCustomObject]@{ displayName = 'Exchange Administrator'; roleTemplateId = 'x' })
            } else {
                @([PSCustomObject]@{ roleDefinition = [PSCustomObject]@{ displayName = 'Global Administrator' } })
            }
        }
    }

    It 'flags an account that holds a role right now' {
        $Result = Get-PSITUserAdminStatus -TenantFilter 'client.test' -UserId 'user-guid'

        $Result.IsAdmin | Should -BeTrue
        $Result.ActiveRoles | Should -Contain 'Exchange Administrator'
    }

    It 'flags an account that can become one on demand' {
        # A badge counting only permanent roles calls this account standard while it can make
        # itself Global Administrator in thirty seconds.
        $Result = Get-PSITUserAdminStatus -TenantFilter 'client.test' -UserId 'user-guid'

        $Result.IsEligible | Should -BeTrue
        $Result.EligibleRoles | Should -Contain 'Global Administrator'
    }

    It 'reads roles transitively, so a role held through a group still counts' {
        $Result = Get-PSITUserAdminStatus -TenantFilter 'client.test' -UserId 'user-guid'
        Should -Invoke New-GraphGetRequest -Times 1 -ParameterFilter { $uri -match 'transitiveMemberOf' }
    }

    It 'reports a standard account as standard, not as unknown' {
        Mock -CommandName New-GraphGetRequest -MockWith { @() }

        $Result = Get-PSITUserAdminStatus -TenantFilter 'client.test' -UserId 'user-guid'

        $Result.IsAdmin | Should -BeFalse
        $Result.IsEligible | Should -BeFalse
        $Result.ActiveRead | Should -BeTrue
        $Result.Warnings | Should -HaveCount 0
    }

    It 'degrades to active-only when the tenant has no PIM, and says so' {
        # No Entra ID P2 means no eligibility to read. That is an answer, not an outage - but a
        # screen must not present it as 'no role can be activated'.
        Mock -CommandName New-GraphGetRequest -MockWith {
            param($uri)
            if ($uri -match 'transitiveMemberOf') {
                @([PSCustomObject]@{ displayName = 'Exchange Administrator' })
            } else {
                throw 'The tenant is not licensed for PIM'
            }
        }

        $Result = Get-PSITUserAdminStatus -TenantFilter 'client.test' -UserId 'user-guid'

        $Result.IsAdmin | Should -BeTrue
        $Result.EligibleRead | Should -BeFalse
        $Result.Warnings[0] | Should -Match 'PIM'
    }

    It 'never claims an account is standard when the roles could not be read' {
        Mock -CommandName New-GraphGetRequest -MockWith { throw 'Graph refused' }

        $Result = Get-PSITUserAdminStatus -TenantFilter 'client.test' -UserId 'user-guid'

        $Result.ActiveRead | Should -BeFalse
        $Result.IsAdmin | Should -BeFalse
        # The pair of fields is what a screen reads: IsAdmin false with ActiveRead false means
        # 'unknown', and must never be shown as 'standard'.
        $Result.Warnings | Should -Not -BeNullOrEmpty
    }

    It 'stamps when the reading was taken, because it is a fact about a moment' {
        $Result = Get-PSITUserAdminStatus -TenantFilter 'client.test' -UserId 'user-guid'
        $Result.ReadUtc | Should -Not -BeNullOrEmpty
    }
}
