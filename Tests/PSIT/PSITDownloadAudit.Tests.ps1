# Pester tests for the mass-download audit search.
#
# The alert says a number and a name; the investigation needs the list. What is pinned here is the
# shape of that answer: a search started once per dossier and filed on it, a window built around
# the alert rather than around now, and a running search reported as running - because a panel
# showing an empty file list instead would read as an account that downloaded nothing.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $script:StartPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Start-PSITDownloadAudit.ps1' -File |
        Select-Object -First 1 -ExpandProperty FullName
    $script:ReadPath = Get-ChildItem -Path (Join-Path $RepoRoot 'Modules') -Recurse -Filter 'Get-PSITDownloadAudit.ps1' -File |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $script:StartPath -or -not $script:ReadPath) { throw 'Could not locate the download audit helpers under Modules/' }

    function New-CippAuditLogSearch {
        param($DisplayName, $TenantFilter, $StartTime, $EndTime, $RecordTypeFilters, $KeywordFilters,
            $OperationsFilters, $UserPrincipalNameFilters, $IPAddressFilters, $ObjectIdFilters)
    }
    function Set-PSITSocCase { param($TenantFilter, $CaseId, $Analyst, $Evidence, $LogAction) }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData, $headers) }
    function New-GraphGetRequest { param($uri, $tenantid, $AsApp, $scope, $NoAuthCheck) }
    function Get-CippAuditLogSearchResults { param($TenantFilter, $QueryId, [switch]$CountOnly) }

    . $script:StartPath
    . $script:ReadPath
}

Describe 'Start-PSITDownloadAudit' {
    BeforeEach {
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName Set-PSITSocCase -MockWith { }
        Mock -CommandName New-CippAuditLogSearch -MockWith {
            [PSCustomObject]@{ id = 'search-1'; displayName = 'PSIT'; status = 'running' }
        }
    }

    It 'asks for the download operations, on the file workloads, for that account' {
        $null = Start-PSITDownloadAudit -TenantFilter 'client.test' -UserPrincipalName 'y.exemple@client.test' -CaseId 'PSIT-SOC-1' -Analyst 'analyste@partner.test' -AroundUtc '2026-08-28T15:27:00Z'

        Should -Invoke New-CippAuditLogSearch -Times 1 -ParameterFilter {
            $UserPrincipalNameFilters -contains 'y.exemple@client.test' -and
            $OperationsFilters -contains 'FileDownloaded' -and
            $RecordTypeFilters -contains 'sharePointFileOperation'
        }
    }

    It 'builds the window around the alert, not around now' {
        # A dossier opened the next morning would otherwise search a day when nothing happened.
        $null = Start-PSITDownloadAudit -TenantFilter 'client.test' -UserPrincipalName 'y.exemple@client.test' -CaseId 'PSIT-SOC-1' -Analyst 'analyste@partner.test' -AroundUtc '2026-08-28T15:27:00Z'

        Should -Invoke New-CippAuditLogSearch -Times 1 -ParameterFilter {
            $StartTime -lt ([datetime]'2026-08-28T15:27:00Z') -and
            $EndTime -gt ([datetime]'2026-08-28T15:27:00Z') -and
            $StartTime -gt ([datetime]'2026-08-27T00:00:00Z')
        }
    }

    It 'files the search on the dossier, so a second visit finds it instead of starting another' {
        $null = Start-PSITDownloadAudit -TenantFilter 'client.test' -UserPrincipalName 'y.exemple@client.test' -CaseId 'PSIT-SOC-1' -Analyst 'analyste@partner.test' -AroundUtc '2026-08-28T15:27:00Z'

        Should -Invoke Set-PSITSocCase -Times 1 -ParameterFilter { $Evidence.download.searchId -eq 'search-1' }
    }

    It 'keeps the search a widened window replaces, so a report can still name its source' {
        $Earlier = [PSCustomObject]@{ searchId = 'search-old'; user = 'y.exemple@client.test'; startUtc = '2026-08-28T03:27:00Z'; endUtc = '2026-08-28T19:27:00Z' }

        $null = Start-PSITDownloadAudit -TenantFilter 'client.test' -UserPrincipalName 'y.exemple@client.test' -CaseId 'PSIT-SOC-1' -Analyst 'analyste@partner.test' -AroundUtc '2026-08-28T15:27:00Z' -HoursBefore 168 -Previous $Earlier

        Should -Invoke Set-PSITSocCase -Times 1 -ParameterFilter {
            $Evidence.download.searchId -eq 'search-1' -and
            $Evidence.download.previous.Count -eq 1 -and
            $Evidence.download.previous[0].searchId -eq 'search-old'
        }
    }

    It 'refuses to report a search that was never created' {
        # Unified auditing off, or the tenant refusing: an empty file list would read as an
        # account that downloaded nothing.
        Mock -CommandName New-CippAuditLogSearch -MockWith { [PSCustomObject]@{ status = 'AuditingDisabledTenant' } }

        { Start-PSITDownloadAudit -TenantFilter 'client.test' -UserPrincipalName 'y.exemple@client.test' -CaseId 'PSIT-SOC-1' -Analyst 'analyste@partner.test' } |
            Should -Throw -ExpectedMessage '*not created*'
        Should -Invoke Set-PSITSocCase -Times 0
    }
}

Describe 'Get-PSITDownloadAudit' {
    BeforeEach {
        Mock -CommandName New-GraphGetRequest -MockWith { [PSCustomObject]@{ status = 'succeeded' } }
        Mock -CommandName Get-CippAuditLogSearchResults -MockWith {
            @(
                [PSCustomObject]@{
                    id              = '1'
                    createdDateTime = '2026-08-28T15:20:00Z'
                    auditData       = [PSCustomObject]@{
                        ObjectId       = 'https://client.sharepoint.com/sites/Compta/Documents partages/Budget 2026.xlsx'
                        SourceFileName = 'Budget 2026.xlsx'
                        SiteUrl        = 'https://client.sharepoint.com/sites/Compta/'
                        Operation      = 'FileDownloaded'
                        CreationTime   = '2026-08-28T15:20:00Z'
                        ClientIP       = '203.0.113.9'
                        UserAgent      = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
                    }
                }
                [PSCustomObject]@{
                    id              = '2'
                    createdDateTime = '2026-08-28T15:24:00Z'
                    auditData       = [PSCustomObject]@{
                        ObjectId       = 'https://client.sharepoint.com/sites/Compta/Documents partages/Contrat.pdf'
                        SourceFileName = 'Contrat.pdf'
                        SiteUrl        = 'https://client.sharepoint.com/sites/Compta/'
                        Operation      = 'FileDownloaded'
                        CreationTime   = '2026-08-28T15:24:00Z'
                        ClientIP       = '203.0.113.9'
                        UserAgent      = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
                    }
                }
                [PSCustomObject]@{
                    id              = '3'
                    createdDateTime = '2026-08-28T15:26:00Z'
                    auditData       = [PSCustomObject]@{
                        ObjectId       = 'https://client.sharepoint.com/sites/RH/Documents partages/Paie.xlsx'
                        SourceFileName = 'Paie.xlsx'
                        SiteUrl        = 'https://client.sharepoint.com/sites/RH/'
                        Operation      = 'FileSyncDownloadedFull'
                        CreationTime   = '2026-08-28T15:26:00Z'
                        ClientIP       = '198.51.100.4'
                        UserAgent      = 'Microsoft SkyDriveSync 24.201.1006.0004'
                    }
                }
            )
        }
    }

    It 'says a running search is running rather than showing an empty list' {
        Mock -CommandName New-GraphGetRequest -MockWith { [PSCustomObject]@{ status = 'running' } }

        $Result = Get-PSITDownloadAudit -TenantFilter 'client.test' -SearchId 'search-1'

        $Result.Running | Should -BeTrue
        $Result.Records | Should -HaveCount 0
        Should -Invoke Get-CippAuditLogSearchResults -Times 0
    }

    It 'answers what was taken, not a page of raw records' {
        $Result = Get-PSITDownloadAudit -TenantFilter 'client.test' -SearchId 'search-1'

        $Result.Summary.FileCount | Should -Be 3
        $Result.Summary.SiteCount | Should -Be 2
        # The shape a client asks about: which kinds of file, over which minutes, from where.
        ($Result.Summary.Extensions | Where-Object { $_.Extension -eq 'xlsx' }).Count | Should -Be 2
        $Result.Summary.FirstUtc | Should -Be '2026-08-28T15:20:00Z'
        $Result.Summary.LastUtc | Should -Be '2026-08-28T15:26:00Z'
        $Result.Summary.AddressCount | Should -Be 2
        $Result.Summary.Agents | Should -HaveCount 2
        # Accessed is not downloaded: the report leans on this split.
        ($Result.Summary.Operations | Where-Object { $_.Operation -eq 'FileDownloaded' }).Count | Should -Be 2
        ($Result.Summary.Operations | Where-Object { $_.Operation -eq 'FileSyncDownloadedFull' }).Count | Should -Be 1
    }

    It 'names each file the way a human would, not by its site path' {
        $Result = Get-PSITDownloadAudit -TenantFilter 'client.test' -SearchId 'search-1'

        # A name split off the URL would arrive percent-encoded; the schema carries the real one.
        $Budget = $Result.Records | Where-Object { $_.Name -eq 'Budget 2026.xlsx' }
        $Budget | Should -Not -BeNullOrEmpty
        $Budget.Path | Should -BeLike '*/Documents partages/Budget 2026.xlsx'
    }

    It 'keeps each file with its site, its hour and its client' {
        $Result = Get-PSITDownloadAudit -TenantFilter 'client.test' -SearchId 'search-1'

        $Paie = $Result.Records | Where-Object { $_.Name -eq 'Paie.xlsx' }
        $Paie.Site | Should -Be 'https://client.sharepoint.com/sites/RH/'
        $Paie.Operation | Should -Be 'FileSyncDownloadedFull'
        # Sync client or browser: the same file count tells two different stories.
        $Paie.Agent | Should -BeLike '*SkyDriveSync*'
    }

    It 'reports an unreadable result rather than an empty one' {
        Mock -CommandName Get-CippAuditLogSearchResults -MockWith { throw 'Graph refused' }

        $Result = Get-PSITDownloadAudit -TenantFilter 'client.test' -SearchId 'search-1'

        $Result.Summary.FileCount | Should -Be 0
        $Result.Warnings[0] | Should -Match 'Résultats illisibles'
    }
}
