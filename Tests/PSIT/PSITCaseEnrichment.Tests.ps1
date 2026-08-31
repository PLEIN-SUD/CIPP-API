# Pester tests for the ingestion-time enrichment.
#
# The worker runs from the cippqueue dispatcher, which swallows exceptions: what these tests pin
# is therefore its self-reliance - one failed read never costs the others, a re-queued dossier
# re-files the same keys instead of duplicating, and a dossier that no longer exists logs and
# returns instead of throwing into the void.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Start-PSITCaseEnrichment.ps1')

    function Get-PSITSocCase { param($TenantFilter, $CaseId, $Status, $Source, $ExternalRef) }
    function Set-PSITSocCase { param($TenantFilter, $CaseId, $Analyst, $Entities, $Evidence, $LogAction) }
    function Get-PSITUserAdminStatus { param($TenantFilter, $UserId) }
    function Start-PSITDownloadAudit { param($TenantFilter, $UserPrincipalName, $CaseId, $Analyst, $AroundUtc, $HoursBefore, $HoursAfter, $Previous) }
    function New-GraphGetRequest { param($uri, $tenantid, $AsApp, $scope, $NoAuthCheck) }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $headers, $LogData) }

    function New-Case {
        param([hashtable]$Overrides = @{})
        $Case = @{
            CaseId     = 'PSIT-SOC-1'
            Tenant     = 'client.test'
            TypeId     = 2
            CreatedUtc = '2026-09-02T08:00:00Z'
            Entities   = [pscustomobject]@{ upn = 'p.martin@client.test' }
            Evidence   = [pscustomobject]@{}
        }
        foreach ($Key in $Overrides.Keys) { $Case[$Key] = $Overrides[$Key] }
        [pscustomobject]$Case
    }
}

Describe 'Start-PSITCaseEnrichment' {
    BeforeEach {
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName Set-PSITSocCase -MockWith { }
        Mock -CommandName New-GraphGetRequest -MockWith { [pscustomobject]@{ id = 'user-guid' } }
        Mock -CommandName Get-PSITUserAdminStatus -MockWith {
            [pscustomobject]@{
                UserId = 'user-guid'; IsAdmin = $true; IsEligible = $false
                ActiveRoles = @('Global Administrator'); EligibleRoles = @()
                ActiveRead = $true; EligibleRead = $true; ReadUtc = '2026-09-02T08:01:00Z'
            }
        }
        Mock -CommandName Start-PSITDownloadAudit -MockWith { [pscustomobject]@{ SearchId = 'search-1' } }
    }

    It 'resolves the user id from the UPN, writes it back on the entities, and files the admin status' {
        Mock -CommandName Get-PSITSocCase -MockWith { New-Case }

        Start-PSITCaseEnrichment -TenantFilter 'client.test' -CaseId 'PSIT-SOC-1'

        Should -Invoke Set-PSITSocCase -Times 1 -ParameterFilter { $Entities -and $Entities['userId'] -eq 'user-guid' }
        Should -Invoke Set-PSITSocCase -Times 1 -ParameterFilter { $Evidence.identity.isAdmin -eq $true }
        Should -Invoke Set-PSITSocCase -Times 1 -ParameterFilter { $LogAction.Action -eq 'enriched' }
    }

    It 'starts the audit search for a type 20 dossier, anchored on the dossier itself' {
        Mock -CommandName Get-PSITSocCase -MockWith { New-Case -Overrides @{ TypeId = 20 } }

        Start-PSITCaseEnrichment -TenantFilter 'client.test' -CaseId 'PSIT-SOC-1'

        Should -Invoke Start-PSITDownloadAudit -Times 1 -ParameterFilter {
            $UserPrincipalName -eq 'p.martin@client.test' -and $AroundUtc -eq '2026-09-02T08:00:00Z'
        }
    }

    It 'never starts a second search on a re-queued dossier: idempotence over the dispatcher' {
        Mock -CommandName Get-PSITSocCase -MockWith {
            New-Case -Overrides @{
                TypeId   = 20
                Evidence = [pscustomobject]@{ download = [pscustomobject]@{ searchId = 'search-old' } }
            }
        }

        Start-PSITCaseEnrichment -TenantFilter 'client.test' -CaseId 'PSIT-SOC-1'

        Should -Invoke Start-PSITDownloadAudit -Times 0
    }

    It 'does not re-read the admin status a dossier already carries' {
        Mock -CommandName Get-PSITSocCase -MockWith {
            New-Case -Overrides @{
                Entities = [pscustomobject]@{ upn = 'p.martin@client.test'; userId = 'user-guid' }
                Evidence = [pscustomobject]@{ identity = [pscustomobject]@{ isAdmin = $false; readUtc = 'x' } }
            }
        }

        Start-PSITCaseEnrichment -TenantFilter 'client.test' -CaseId 'PSIT-SOC-1'

        Should -Invoke Get-PSITUserAdminStatus -Times 0
    }

    It 'files the recent dossiers naming the same entity, and never itself' {
        $Sibling = New-Case -Overrides @{ CaseId = 'PSIT-SOC-0'; CreatedUtc = '2026-08-30T08:00:00Z' }
        $Unrelated = New-Case -Overrides @{ CaseId = 'PSIT-SOC-9'; Entities = [pscustomobject]@{ upn = 'autre@client.test' } }
        Mock -CommandName Get-PSITSocCase -MockWith {
            if ($CaseId) { return (New-Case) }
            @((New-Case), $Sibling, $Unrelated)
        }

        Start-PSITCaseEnrichment -TenantFilter 'client.test' -CaseId 'PSIT-SOC-1'

        Should -Invoke Set-PSITSocCase -Times 1 -ParameterFilter {
            $Evidence.related -and @($Evidence.related.cases).Count -eq 1 -and $Evidence.related.cases[0].caseId -eq 'PSIT-SOC-0'
        }
    }

    It 'a failed identity read never costs the related-case scan' {
        Mock -CommandName New-GraphGetRequest -MockWith { throw 'Graph refused' }
        Mock -CommandName Get-PSITSocCase -MockWith {
            if ($CaseId) { return (New-Case) }
            @((New-Case))
        }

        { Start-PSITCaseEnrichment -TenantFilter 'client.test' -CaseId 'PSIT-SOC-1' } | Should -Not -Throw

        Should -Invoke Set-PSITSocCase -Times 1 -ParameterFilter { $null -ne $Evidence.related }
        Should -Invoke Write-LogMessage -Times 1 -ParameterFilter { $sev -eq 'Warn' -and $message -match 'identity read failed' }
    }

    It 'logs and returns when the dossier is gone: the dispatcher swallows throws' {
        Mock -CommandName Get-PSITSocCase -MockWith { @() }

        { Start-PSITCaseEnrichment -TenantFilter 'client.test' -CaseId 'PSIT-SOC-404' } | Should -Not -Throw

        Should -Invoke Set-PSITSocCase -Times 0
        Should -Invoke Write-LogMessage -Times 1 -ParameterFilter { $message -match 'was not found' }
    }
}
