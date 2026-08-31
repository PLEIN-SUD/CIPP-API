# Pester tests for the typed dossier audit search (types 4, 5 and 7).
#
# The guide steps used to say 'retrouver la creation dans l'audit' and mean a console and a
# notepad. What is pinned here: each type asks its own question (role changes, inbox rules,
# mailbox delegations), the window anchors on the alert rather than on now, the search is filed
# on the dossier, and a running search is said to be running - an empty event list would read
# as 'nothing happened'.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:KindPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Get-PSITAuditSearchKind.ps1' -File |
        Select-Object -First 1 -ExpandProperty FullName
    $script:StartPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Start-PSITCaseAuditSearch.ps1' -File |
        Select-Object -First 1 -ExpandProperty FullName
    $script:ReadPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Get-PSITCaseAuditSearch.ps1' -File |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $script:KindPath -or -not $script:StartPath -or -not $script:ReadPath) { throw 'Could not locate the case audit search helpers under Modules/' }

    function New-CippAuditLogSearch {
        param($DisplayName, $TenantFilter, $StartTime, $EndTime, $RecordTypeFilters, $KeywordFilters,
            $OperationsFilters, $UserPrincipalNameFilters, $IPAddressFilters, $ObjectIdFilters)
    }
    function Set-PSITSocCase { param($TenantFilter, $CaseId, $Analyst, $Evidence, $LogAction) }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData, $headers) }
    function New-GraphGetRequest { param($uri, $tenantid, $AsApp, $scope, $NoAuthCheck) }
    function Get-CippAuditLogSearchResults { param($TenantFilter, $QueryId, [switch]$CountOnly) }

    . $script:KindPath
    . $script:StartPath
    . $script:ReadPath
}

Describe 'Get-PSITAuditSearchKind' {
    It 'knows the question each covered type asks' {
        (Get-PSITAuditSearchKind -TypeId 4).Key | Should -Be 'roles'
        (Get-PSITAuditSearchKind -TypeId 5).Key | Should -Be 'mailbox-rules'
        (Get-PSITAuditSearchKind -TypeId 7).Key | Should -Be 'mailbox-access'
    }

    It 'answers nothing for a type whose evidence does not live in the unified audit log' {
        # Type 20 has its own download search; the others have no audit question at all.
        foreach ($TypeId in @(1, 2, 6, 9, 20, 99)) {
            Get-PSITAuditSearchKind -TypeId $TypeId | Should -BeNullOrEmpty
        }
    }

    It 'asks for role membership changes on a privilege-elevation dossier' {
        $Kind = Get-PSITAuditSearchKind -TypeId 4
        $Kind.RecordTypes | Should -Contain 'azureActiveDirectory'
        $Kind.Operations | Should -Contain 'Add member to role.'
        $Kind.Operations | Should -Contain 'Add eligible member to role.'
    }

    It 'asks for inbox rules and forwarding on a rule dossier' {
        $Kind = Get-PSITAuditSearchKind -TypeId 5
        $Kind.Operations | Should -Contain 'New-InboxRule'
        # Outlook on the web writes UpdateInboxRules, not New-InboxRule: missing it hides the
        # very rules a BEC plants.
        $Kind.Operations | Should -Contain 'UpdateInboxRules'
        # SMTP forwarding is set on the mailbox itself.
        $Kind.Operations | Should -Contain 'Set-Mailbox'
    }

    It 'asks for permissions and delegations on a mailbox-access dossier' {
        $Kind = Get-PSITAuditSearchKind -TypeId 7
        $Kind.Operations | Should -Contain 'Add-MailboxPermission'
        $Kind.Operations | Should -Contain 'Add-RecipientPermission'
    }
}

Describe 'Start-PSITCaseAuditSearch' {
    BeforeEach {
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName Set-PSITSocCase -MockWith { }
        Mock -CommandName New-CippAuditLogSearch -MockWith {
            [PSCustomObject]@{ id = 'search-1'; displayName = 'PSIT'; status = 'running' }
        }
    }

    It 'asks the type its own question, for that account' {
        $null = Start-PSITCaseAuditSearch -TenantFilter 'client.test' -TypeId 5 -UserPrincipalName 'y.exemple@client.test' -CaseId 'PSIT-SOC-1' -Analyst 'analyste@partner.test' -AroundUtc '2026-08-28T15:27:00Z'

        Should -Invoke New-CippAuditLogSearch -Times 1 -ParameterFilter {
            $UserPrincipalNameFilters -contains 'y.exemple@client.test' -and
            $OperationsFilters -contains 'New-InboxRule' -and
            $RecordTypeFilters -contains 'exchangeAdmin'
        }
    }

    It 'builds the window around the alert, not around now' {
        $null = Start-PSITCaseAuditSearch -TenantFilter 'client.test' -TypeId 4 -UserPrincipalName 'y.exemple@client.test' -CaseId 'PSIT-SOC-1' -Analyst 'analyste@partner.test' -AroundUtc '2026-08-28T15:27:00Z'

        Should -Invoke New-CippAuditLogSearch -Times 1 -ParameterFilter {
            $StartTime -lt ([datetime]'2026-08-28T15:27:00Z') -and
            $EndTime -gt ([datetime]'2026-08-28T15:27:00Z') -and
            $StartTime -gt ([datetime]'2026-08-25T00:00:00Z')
        }
    }

    It 'files the search on the dossier under its own key, with its kind' {
        # Evidence.audit, not Evidence.download: a type 20 dossier keeps both without collision.
        $null = Start-PSITCaseAuditSearch -TenantFilter 'client.test' -TypeId 7 -UserPrincipalName 'y.exemple@client.test' -CaseId 'PSIT-SOC-1' -Analyst 'analyste@partner.test' -AroundUtc '2026-08-28T15:27:00Z'

        Should -Invoke Set-PSITSocCase -Times 1 -ParameterFilter {
            $Evidence.audit.searchId -eq 'search-1' -and $Evidence.audit.kind -eq 'mailbox-access'
        }
    }

    It 'keeps the search a widened window replaces, so a report can still name its source' {
        $Earlier = [PSCustomObject]@{ searchId = 'search-old'; user = 'y.exemple@client.test'; startUtc = '2026-08-26T15:27:00Z'; endUtc = '2026-08-28T19:27:00Z' }

        $null = Start-PSITCaseAuditSearch -TenantFilter 'client.test' -TypeId 5 -UserPrincipalName 'y.exemple@client.test' -CaseId 'PSIT-SOC-1' -Analyst 'analyste@partner.test' -AroundUtc '2026-08-28T15:27:00Z' -HoursBefore 168 -Previous $Earlier

        Should -Invoke Set-PSITSocCase -Times 1 -ParameterFilter {
            $Evidence.audit.searchId -eq 'search-1' -and
            $Evidence.audit.previous.Count -eq 1 -and
            $Evidence.audit.previous[0].searchId -eq 'search-old'
        }
    }

    It 'refuses a type that has no audit question, rather than searching for nothing' {
        { Start-PSITCaseAuditSearch -TenantFilter 'client.test' -TypeId 2 -UserPrincipalName 'y.exemple@client.test' -CaseId 'PSIT-SOC-1' -Analyst 'analyste@partner.test' } |
            Should -Throw -ExpectedMessage '*no audit search defined*'
        Should -Invoke New-CippAuditLogSearch -Times 0
    }

    It 'refuses to report a search that was never created' {
        Mock -CommandName New-CippAuditLogSearch -MockWith { [PSCustomObject]@{ status = 'AuditingDisabledTenant' } }

        { Start-PSITCaseAuditSearch -TenantFilter 'client.test' -TypeId 4 -UserPrincipalName 'y.exemple@client.test' -CaseId 'PSIT-SOC-1' -Analyst 'analyste@partner.test' } |
            Should -Throw -ExpectedMessage '*not created*'
        Should -Invoke Set-PSITSocCase -Times 0
    }
}

Describe 'Get-PSITCaseAuditSearch' {
    BeforeEach {
        Mock -CommandName New-GraphGetRequest -MockWith { [PSCustomObject]@{ status = 'succeeded' } }
        Mock -CommandName Get-CippAuditLogSearchResults -MockWith {
            @(
                [PSCustomObject]@{
                    id              = '1'
                    createdDateTime = '2026-08-28T15:20:00Z'
                    auditData       = [PSCustomObject]@{
                        Operation    = 'New-InboxRule'
                        UserId       = 'y.exemple@client.test'
                        ObjectId     = $null
                        CreationTime = '2026-08-28T15:20:00Z'
                        ClientIP     = '203.0.113.9'
                        Parameters   = @(
                            [PSCustomObject]@{ Name = 'Name'; Value = '.' }
                            [PSCustomObject]@{ Name = 'DeleteMessage'; Value = 'True' }
                            [PSCustomObject]@{ Name = 'Identity'; Value = 'y.exemple@client.test' }
                        )
                    }
                }
                [PSCustomObject]@{
                    id              = '2'
                    createdDateTime = '2026-08-28T15:24:00Z'
                    auditData       = [PSCustomObject]@{
                        Operation    = 'Set-Mailbox'
                        UserId       = 'y.exemple@client.test'
                        ObjectId     = 'y.exemple@client.test'
                        CreationTime = '2026-08-28T15:24:00Z'
                        ClientIP     = '198.51.100.4'
                        Parameters   = @([PSCustomObject]@{ Name = 'ForwardingSmtpAddress'; Value = 'smtp:pivot@exemple.net' })
                    }
                }
            )
        }
    }

    It 'says a running search is running rather than showing an empty list' {
        Mock -CommandName New-GraphGetRequest -MockWith { [PSCustomObject]@{ status = 'running' } }

        $Result = Get-PSITCaseAuditSearch -TenantFilter 'client.test' -SearchId 'search-1'

        $Result.Running | Should -BeTrue
        $Result.Records | Should -HaveCount 0
        Should -Invoke Get-CippAuditLogSearchResults -Times 0
    }

    It 'maps each record to what an analyst asks: when, what, who, on what, from where' {
        $Result = Get-PSITCaseAuditSearch -TenantFilter 'client.test' -SearchId 'search-1'

        $Rule = $Result.Records | Where-Object { $_.Operation -eq 'New-InboxRule' }
        $Rule.Actor | Should -Be 'y.exemple@client.test'
        $Rule.Ip | Should -Be '203.0.113.9'
        # The rule's substance (name, delete flag) travels in the compact detail.
        $Rule.Detail | Should -Match 'DeleteMessage'
        # A record without ObjectId still names its target, through the parameters.
        $Rule.Target | Should -Be 'y.exemple@client.test'
    }

    It 'summarises what happened: counts by operation, actors, addresses, bounds' {
        $Result = Get-PSITCaseAuditSearch -TenantFilter 'client.test' -SearchId 'search-1'

        $Result.Summary.EventCount | Should -Be 2
        ($Result.Summary.Operations | Where-Object { $_.Operation -eq 'New-InboxRule' }).Count | Should -Be 1
        $Result.Summary.Actors[0].Actor | Should -Be 'y.exemple@client.test'
        $Result.Summary.AddressCount | Should -Be 2
        $Result.Summary.FirstUtc | Should -Be '2026-08-28T15:20:00Z'
        $Result.Summary.LastUtc | Should -Be '2026-08-28T15:24:00Z'
    }

    It 'reports an unreadable result rather than an empty one' {
        Mock -CommandName Get-CippAuditLogSearchResults -MockWith { throw 'Graph refused' }

        $Result = Get-PSITCaseAuditSearch -TenantFilter 'client.test' -SearchId 'search-1'

        $Result.Summary.EventCount | Should -Be 0
        $Result.Warnings[0] | Should -Match 'Résultats illisibles'
    }
}
