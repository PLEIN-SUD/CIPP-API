# Pester tests for Get-PSITSocAnalysts.
#
# The reassignment picker's data: portal users from the allowedUsers table, display names joined
# from Graph on the partner tenant. What is pinned here is the degradation contract - a Graph
# outage yields email-only entries with a named warning, never an empty list, because handing a
# case over is exactly the gesture an outage should not block.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Get-PSITSocAnalysts.ps1' -File |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $FunctionPath) { throw 'Could not locate Get-PSITSocAnalysts.ps1 under Modules/' }

    function Get-CippTable { param($tablename) }
    function Get-CIPPAzDataTableEntity { param($Context, $Filter) }
    function New-GraphGetRequest { param($uri, $tenantid, $NoAuthCheck) }

    . $FunctionPath
}

Describe 'Get-PSITSocAnalysts' {
    BeforeEach {
        Mock -CommandName Get-CippTable -MockWith { @{ Context = 'allowedUsers' } }
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith {
            @(
                [PSCustomObject]@{ RowKey = 'b.analyste@partner.test' }
                [PSCustomObject]@{ RowKey = 'a.analyste@partner.test' }
                [PSCustomObject]@{ RowKey = '_bookkeeping' }
            )
        }
        Mock -CommandName New-GraphGetRequest -MockWith {
            @(
                [PSCustomObject]@{ userPrincipalName = 'A.Analyste@partner.test'; displayName = 'Alice Analyste' }
                [PSCustomObject]@{ userPrincipalName = 'b.analyste@partner.test'; displayName = 'Bob Analyste' }
            )
        }
    }

    It 'joins display names to portal users, matching the UPN regardless of case' {
        $Result = Get-PSITSocAnalysts

        $Result.Analysts | Should -HaveCount 2
        ($Result.Analysts | Where-Object { $_.userPrincipalName -eq 'a.analyste@partner.test' }).displayName |
            Should -Be 'Alice Analyste'
        $Result.Warnings | Should -HaveCount 0
    }

    It 'skips the table bookkeeping rows' {
        $Result = Get-PSITSocAnalysts
        $Result.Analysts.userPrincipalName | Should -Not -Contain '_bookkeeping'
    }

    It 'sorts by display name so the picker reads like a team list' {
        $Result = Get-PSITSocAnalysts
        $Result.Analysts[0].displayName | Should -Be 'Alice Analyste'
    }

    It 'degrades to email-only entries with a named warning when Graph fails' {
        Mock -CommandName New-GraphGetRequest -MockWith { throw 'tenant did not answer' }

        $Result = Get-PSITSocAnalysts

        $Result.Analysts | Should -HaveCount 2
        $Result.Analysts[0].displayName | Should -Be ''
        $Result.Warnings | Should -HaveCount 1
        $Result.Warnings[0] | Should -Match 'Display names unavailable'
    }

    It 'reports a Graph that answered nothing, instead of showing addresses in silence' {
        # The state that cost an afternoon of guessing: no error, no warning, and no names. An
        # outage was reported; an empty answer was not, and the screen looked identical.
        Mock -CommandName New-GraphGetRequest -MockWith { @() }

        $Result = Get-PSITSocAnalysts

        $Result.Analysts | Should -HaveCount 2
        $Result.Warnings | Should -HaveCount 1
        $Result.Warnings[0] | Should -Match 'without a single user'
    }

    It 'reports two lists that exist and never meet, with both counts' {
        Mock -CommandName New-GraphGetRequest -MockWith {
            @([PSCustomObject]@{ userPrincipalName = 'quelquun.dautre@partner.test'; displayName = 'Quelqu un' })
        }

        $Result = Get-PSITSocAnalysts

        $Result.Warnings[0] | Should -Match 'none of the 2 portal users matched any of the 1 accounts'
    }

    It 'unwraps a response envelope rather than reporting an outage that did not happen' {
        # If the helper ever hands back the envelope, every row fails the userPrincipalName
        # filter and the join answers no names with nothing wrong on the wire.
        Mock -CommandName New-GraphGetRequest -MockWith {
            [PSCustomObject]@{
                value = @(
                    [PSCustomObject]@{ userPrincipalName = 'a.analyste@partner.test'; displayName = 'Alice Analyste' }
                )
            }
        }

        $Result = Get-PSITSocAnalysts

        ($Result.Analysts | Where-Object { $_.userPrincipalName -eq 'a.analyste@partner.test' }).displayName |
            Should -Be 'Alice Analyste'
        $Result.Warnings | Should -HaveCount 0
    }

    It 'answers an empty table with an empty list and no Graph call' {
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith { @() }

        $Result = Get-PSITSocAnalysts

        $Result.Analysts | Should -HaveCount 0
        Should -Invoke New-GraphGetRequest -Times 0
    }
}

Describe 'Invoke-PSITListSocAnalysts access declaration' {
    # The bug this pins: the endpoint declared Entrypoint alone. The front calls it without a
    # tenantFilter - it has no tenant to filter on - so the access check fell back to the partner
    # tenant, which no customer-scoped role may see, and the endpoint answered 403 to everyone.
    # The queue then showed addresses where names belong and the reassignment picker stayed empty,
    # with nothing in the code saying why. Every other PSIT endpoint takes a real tenantFilter;
    # this is the only tenant-agnostic one, so it is the only one that needs the declaration.
    BeforeAll {
        $Root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
        $script:EndpointPath = Get-ChildItem -Path (Join-Path $Root 'Modules') -Recurse -Filter 'Invoke-PSITListSocAnalysts.ps1' -File |
            Select-Object -First 1 -ExpandProperty FullName
    }

    It 'is declared AnyTenant, without which it answers 403 to every customer-scoped role' {
        $script:EndpointPath | Should -Not -BeNullOrEmpty
        $Source = [System.IO.File]::ReadAllText($script:EndpointPath)
        $Source | Should -Match '(?m)^\s*Entrypoint,AnyTenant\s*$'
    }

    It 'still asks for a role: AnyTenant widens the tenant, never the permission' {
        $Source = [System.IO.File]::ReadAllText($script:EndpointPath)
        $Source | Should -Match '(?m)^\s*Security\.Incident\.Read\s*$'
    }
}
