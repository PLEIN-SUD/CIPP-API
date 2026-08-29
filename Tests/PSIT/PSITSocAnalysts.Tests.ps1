# Pester tests for Get-PSITSocAnalysts.
#
# The reassignment picker's data. Two sources in order of authority: the portal's own roster
# (allowedUsers), and the partner tenant's accounts when that roster is empty - which it is on
# every deployment that does not map Entra groups to CIPP roles, and where the first shape of
# this endpoint answered 'No options' with nothing anywhere saying why.
#
# What is pinned: the picker is never empty when the tenant can answer, no way of coming back
# without names is silent, and none of them empties the list - addresses are shown, because
# handing a dossier over is exactly the gesture an outage should not block.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $FunctionPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Get-PSITSocAnalysts.ps1' -File |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $FunctionPath) { throw 'Could not locate Get-PSITSocAnalysts.ps1 under Modules/' }

    function Get-CippTable { param($tablename) }
    function Get-CIPPAzDataTableEntity { param($Context, $Filter) }
    function New-GraphGetRequest { param($uri, $tenantid, $NoAuthCheck, $AsApp) }
    function Get-PSITSocAnalystGroup { }

    . $FunctionPath
}

Describe 'Get-PSITSocAnalysts with a portal roster' {
    BeforeEach {
        Mock -CommandName Get-PSITSocAnalystGroup -MockWith { $null }
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
                [PSCustomObject]@{ userPrincipalName = 'A.Analyste@partner.test'; displayName = 'Alice Analyste'; accountEnabled = $true; userType = 'Member' }
                [PSCustomObject]@{ userPrincipalName = 'b.analyste@partner.test'; displayName = 'Bob Analyste'; accountEnabled = $true; userType = 'Member' }
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

    It 'keeps the roster and reports the outage when Graph fails' {
        Mock -CommandName New-GraphGetRequest -MockWith { throw 'tenant did not answer' }

        $Result = Get-PSITSocAnalysts

        $Result.Analysts | Should -HaveCount 2
        $Result.Analysts[0].displayName | Should -Be ''
        $Result.Warnings[0] | Should -Match "n'a pas répondu"
    }

    It 'reports a Graph that answered nothing, instead of showing addresses in silence' {
        Mock -CommandName New-GraphGetRequest -MockWith { @() }

        $Result = Get-PSITSocAnalysts

        $Result.Analysts | Should -HaveCount 2
        $Result.Warnings[0] | Should -Match 'sans aucun compte'
    }

    It 'reports two lists that exist and never meet, with both counts' {
        Mock -CommandName New-GraphGetRequest -MockWith {
            @([PSCustomObject]@{ userPrincipalName = 'quelquun.dautre@partner.test'; displayName = 'Quelqu un'; accountEnabled = $true; userType = 'Member' })
        }

        $Result = Get-PSITSocAnalysts

        $Result.Warnings[0] | Should -Match 'aucun des 2 utilisateurs du portail ne correspond aux 1 comptes'
    }

    It 'unwraps a response envelope rather than reporting an outage that did not happen' {
        Mock -CommandName New-GraphGetRequest -MockWith {
            [PSCustomObject]@{
                value = @(
                    [PSCustomObject]@{ userPrincipalName = 'a.analyste@partner.test'; displayName = 'Alice Analyste'; accountEnabled = $true; userType = 'Member' }
                )
            }
        }

        $Result = Get-PSITSocAnalysts

        ($Result.Analysts | Where-Object { $_.userPrincipalName -eq 'a.analyste@partner.test' }).displayName |
            Should -Be 'Alice Analyste'
        $Result.Warnings | Should -HaveCount 0
    }
}

Describe 'Get-PSITSocAnalysts without a portal roster' {
    # The state seen in production: allowedUsers is what the CIPP Users page maintains, by hand or
    # from the Entra-group sync. A portal whose access is granted only through the static web
    # app invitations has an empty table while people use it daily, and the picker offered nothing.
    BeforeEach {
        Mock -CommandName Get-PSITSocAnalystGroup -MockWith { $null }
        Mock -CommandName Get-CippTable -MockWith { @{ Context = 'allowedUsers' } }
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith { @() }
        Mock -CommandName New-GraphGetRequest -MockWith {
            @(
                [PSCustomObject]@{ userPrincipalName = 'a.analyste@partner.test'; displayName = 'Alice Analyste'; accountEnabled = $true; userType = 'Member' }
                [PSCustomObject]@{ userPrincipalName = 'parti@partner.test'; displayName = 'Compte desactive'; accountEnabled = $false; userType = 'Member' }
                [PSCustomObject]@{ userPrincipalName = 'invite@ailleurs.test'; displayName = 'Invite'; accountEnabled = $true; userType = 'Guest' }
            )
        }
    }

    It 'lists the tenant accounts rather than offering nothing' {
        $Result = Get-PSITSocAnalysts

        $Result.Analysts | Should -HaveCount 1
        $Result.Analysts[0].displayName | Should -Be 'Alice Analyste'
    }

    It 'says the list is the directory as a note, not a warning above the triage queue' {
        $Result = Get-PSITSocAnalysts
        $Result.Notes[0] | Should -Match 'liste des utilisateurs du portail est vide'
    }

    It 'leaves out disabled accounts and guests, who cannot hold a dossier' {
        $Result = Get-PSITSocAnalysts
        $Result.Analysts.userPrincipalName | Should -Not -Contain 'parti@partner.test'
        $Result.Analysts.userPrincipalName | Should -Not -Contain 'invite@ailleurs.test'
    }

    It 'answers an empty list, and says why, when neither source has anything' {
        Mock -CommandName New-GraphGetRequest -MockWith { @() }

        $Result = Get-PSITSocAnalysts

        $Result.Analysts | Should -HaveCount 0
        $Result.Warnings | Should -HaveCount 1
    }
}


Describe 'Get-PSITSocAnalysts with a configured group' {
    # A group names the team, which neither the portal roster nor the tenant directory does.
    # When one is set it answers alone: falling back to a wider list would quietly offer the
    # very people the group was chosen to exclude.
    BeforeEach {
        Mock -CommandName Get-PSITSocAnalystGroup -MockWith {
            [PSCustomObject]@{ GroupId = '00000000-0000-0000-0000-000000000001'; GroupName = 'Analystes SOC' }
        }
        Mock -CommandName Get-CippTable -MockWith { @{ Context = 'allowedUsers' } }
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith {
            @([PSCustomObject]@{ RowKey = 'quelquun.dautre@partner.test' })
        }
        Mock -CommandName New-GraphGetRequest -MockWith {
            @(
                [PSCustomObject]@{ userPrincipalName = 'a.analyste@partner.test'; displayName = 'Alice Analyste'; accountEnabled = $true }
                [PSCustomObject]@{ userPrincipalName = 'parti@partner.test'; displayName = 'Compte desactive'; accountEnabled = $false }
                [PSCustomObject]@{ id = 'un-groupe-imbrique'; displayName = 'Sous-groupe' }
            )
        }
    }

    It 'proposes the group members and nobody else' {
        $Result = Get-PSITSocAnalysts

        $Result.Analysts | Should -HaveCount 1
        $Result.Analysts[0].userPrincipalName | Should -Be 'a.analyste@partner.test'
        # The portal roster is not consulted at all: the group is the stated intent.
        $Result.Analysts.userPrincipalName | Should -Not -Contain 'quelquun.dautre@partner.test'
    }

    It 'reads members transitively, so a nested group still holds analysts' {
        $Result = Get-PSITSocAnalysts
        Should -Invoke New-GraphGetRequest -Times 1 -ParameterFilter { $uri -match 'transitiveMembers' }
    }

    It 'leaves out a group member that is not an enabled user' {
        $Result = Get-PSITSocAnalysts
        $Result.Analysts.userPrincipalName | Should -Not -Contain 'parti@partner.test'
    }

    It 'proposes nobody, and says why, when the group cannot be read' {
        Mock -CommandName New-GraphGetRequest -MockWith { throw 'group not found' }

        $Result = Get-PSITSocAnalysts

        $Result.Analysts | Should -HaveCount 0
        $Result.Warnings[0] | Should -Match "n'a pas pu être lu"
    }

    It 'says the group is empty rather than proposing an empty picker in silence' {
        Mock -CommandName New-GraphGetRequest -MockWith { @() }

        $Result = Get-PSITSocAnalysts

        $Result.Analysts | Should -HaveCount 0
        $Result.Warnings[0] | Should -Match 'aucun utilisateur actif'
    }
}

Describe 'Invoke-PSITListSocAnalysts access declaration' {
    # The bug this pins: the endpoint declared Entrypoint alone. The front calls it without a
    # tenantFilter - it has no tenant to filter on - so the access check fell back to the partner
    # tenant, which no customer-scoped role may see, and the endpoint answered 403 to everyone.
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
