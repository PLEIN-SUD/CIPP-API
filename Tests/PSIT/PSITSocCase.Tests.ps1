# Pester tests for the SOC case store: the unit of work of the SOC triage dashboard.
#
# The case is an audit trail, so the tests pin the properties that make it one: a qualification
# carries a name and a timestamp and keeps its history when it changes; adoption of the same
# external incident twice yields one case; the action log records what happened, including its
# own truncation; and a stored row that lost a JSON field still renders instead of sinking the
# whole queue.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Get-PSITSocCase.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Set-PSITSocCase.ps1')

    function Get-CippTable { param($tablename) @{ Table = $tablename } }
    function Get-CIPPAzDataTableEntity { param($Table, $Filter) }
    function Add-CIPPAzDataTableEntity { param($Table, $Entity, [switch]$Force) }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $headers, $LogData) }

    # An in-memory table: Add upserts on PartitionKey+RowKey, Get honours the two filter shapes
    # the functions actually emit. Enough to exercise create-then-update round trips without
    # Azurite.
    function Reset-Store { $script:Store = @{} }
    function Enable-StoreMocks {
        Mock -CommandName Add-CIPPAzDataTableEntity -MockWith {
            $script:Store["$($Entity.PartitionKey)|$($Entity.RowKey)"] = [pscustomobject]$Entity
        }
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith {
            $Rows = @($script:Store.Values)
            if ($Filter -match "PartitionKey eq '([^']+)'") { $Rows = @($Rows | Where-Object { $_.PartitionKey -eq $Matches[1] }) }
            if ($Filter -match "RowKey eq '([^']+)'") { $Rows = @($Rows | Where-Object { $_.RowKey -eq $Matches[1] }) }
            $Rows
        }
    }
}

Describe 'Set-PSITSocCase, creation' {
    BeforeEach {
        Reset-Store
        Enable-StoreMocks
        Mock -CommandName Write-LogMessage -MockWith { }
    }

    It 'creates a case with a dated, quotable reference and the creation stamps' {
        $Case = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'analyste@example.test' -Source 'xdr' -TypeId 15 -Title 'Infostealer activity on PC-042'

        $Case.CaseId | Should -Match '^PSIT-SOC-\d{8}-[0-9A-F]{4}$'
        $Case.Status | Should -Be 'new'
        $Case.CreatedBy | Should -Be 'analyste@example.test'
        $Case.CreatedUtc | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$'
        @($Case.ActionLog | Where-Object { $_.Action -eq 'created' }).Count | Should -Be 1
    }

    It 'refuses type 8: Google Workspace is out of the CIPP scope' {
        { Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'a' -Source 'manual' -TypeId 8 -Title 'x' } |
            Should -Throw '*out of the CIPP scope*'
    }

    It 'requires Source, TypeId and Title to create' {
        { Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'a' -Source 'extsoc' -Title 'x' } |
            Should -Throw '*requires TypeId*'
    }

    It 'adopting the same external incident twice yields one case, not two' {
        $First = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'a' -Source 'xdr' -TypeId 13 -Title 'Malware blocked' -ExternalRef 'INC-12345'
        $Second = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'b' -Source 'xdr' -TypeId 13 -Title 'Malware blocked' -ExternalRef 'INC-12345'

        $Second.CaseId | Should -Be $First.CaseId
        $script:Store.Count | Should -Be 1
    }

    It 'a closed case does not block a new adoption of the same reference' {
        $First = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'a' -Source 'xdr' -TypeId 13 -Title 'Malware blocked' -ExternalRef 'INC-12345'
        $null = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'a' -CaseId $First.CaseId -Status 'closed'

        $Second = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'a' -Source 'xdr' -TypeId 13 -Title 'Malware blocked again' -ExternalRef 'INC-12345'
        $Second.CaseId | Should -Not -Be $First.CaseId
    }
}

Describe 'Set-PSITSocCase, qualification' {
    BeforeEach {
        Reset-Store
        Enable-StoreMocks
        Mock -CommandName Write-LogMessage -MockWith { }
        $script:Case = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'a' -Source 'extsoc' -TypeId 2 -Title 'Voyage impossible p.martin'
    }

    It 'records the verdict with the analyst and a timestamp, and derives the status' {
        $Case = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'analyste@example.test' -CaseId $script:Case.CaseId -Verdict 'true-positive' -Justification 'AiTM: même session vue de deux pays'

        $Case.Qualification.Verdict | Should -Be 'true-positive'
        $Case.Qualification.Analyst | Should -Be 'analyste@example.test'
        $Case.Qualification.DecidedUtc | Should -Not -BeNullOrEmpty
        $Case.Status | Should -Be 'qualified-tp'
    }

    It 'a false positive derives qualified-fp, an undetermined derives nothing' {
        $Fp = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'a' -CaseId $script:Case.CaseId -Verdict 'false-positive'
        $Fp.Status | Should -Be 'qualified-fp'

        $Undetermined = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'a' -CaseId $script:Case.CaseId -Verdict 'undetermined'
        $Undetermined.Status | Should -Be 'qualified-fp'
    }

    It 'an explicit status in the same call wins over the derived one' {
        $Case = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'a' -CaseId $script:Case.CaseId -Verdict 'true-positive' -Status 'contained'
        $Case.Status | Should -Be 'contained'
    }

    It 'a changed mind stays visible: the previous verdict moves into the history' {
        $null = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'a' -CaseId $script:Case.CaseId -Verdict 'false-positive' -Justification 'VPN'
        $Case = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'b' -CaseId $script:Case.CaseId -Verdict 'true-positive' -Justification 'le client dément le VPN'

        @($Case.Qualification.PreviousVerdicts).Count | Should -Be 1
        $Case.Qualification.PreviousVerdicts[0].Verdict | Should -Be 'false-positive'
        $Case.Qualification.PreviousVerdicts[0].Analyst | Should -Be 'a'
    }

    It 're-saving the same verdict does not pile up identical history rows' {
        $null = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'a' -CaseId $script:Case.CaseId -Verdict 'false-positive' -Justification 'VPN'
        $Case = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'a' -CaseId $script:Case.CaseId -Verdict 'false-positive' -Justification 'VPN'

        @($Case.Qualification.PreviousVerdicts).Count | Should -Be 0
    }

    It 'refuses a justification without a verdict: it would justify nothing' {
        { Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'a' -CaseId $script:Case.CaseId -Justification 'orpheline' } |
            Should -Throw '*Verdict*'
    }
}

Describe 'Set-PSITSocCase, lifecycle and log' {
    BeforeEach {
        Reset-Store
        Enable-StoreMocks
        Mock -CommandName Write-LogMessage -MockWith { }
        $script:Case = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'a' -Source 'mdo' -TypeId 18 -Title 'ZAP incomplet'
    }

    It 'updating a case that does not exist is an error, not a silent create' {
        { Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'a' -CaseId 'PSIT-SOC-20260101-XXXX' -Status 'investigating' } |
            Should -Throw '*does not exist*'
    }

    It 'closing stamps who and when; reopening clears the stamps and says so' {
        $Closed = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'closer@example.test' -CaseId $script:Case.CaseId -Status 'closed'
        $Closed.ClosedBy | Should -Be 'closer@example.test'
        $Closed.ClosedUtc | Should -Not -BeNullOrEmpty

        $Reopened = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'b' -CaseId $script:Case.CaseId -Status 'investigating'
        $Reopened.ClosedUtc | Should -BeNullOrEmpty
        @($Reopened.ActionLog | Where-Object { $_.Action -eq 'reopened' }).Count | Should -Be 1
    }

    It 'merges guide progress per step and keeps who checked it' {
        $null = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'a' -CaseId $script:Case.CaseId -GuideProgress @(@{ StepId = 'check-trace'; State = 'done' })
        $Case = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'b' -CaseId $script:Case.CaseId -GuideProgress @(@{ StepId = 'check-quarantine'; State = 'skipped' })

        $Case.GuideProgress.'check-trace'.State | Should -Be 'done'
        $Case.GuideProgress.'check-trace'.By | Should -Be 'a'
        $Case.GuideProgress.'check-quarantine'.State | Should -Be 'skipped'
    }

    It 'rejects a guide state outside the vocabulary' {
        { Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'a' -CaseId $script:Case.CaseId -GuideProgress @(@{ StepId = 'x'; State = 'peut-être' }) } |
            Should -Throw '*Invalid guide step state*'
    }

    It 'records an action taken outside CIPP with the analyst who declares it' {
        $Case = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'analyste@example.test' -CaseId $script:Case.CaseId -LogAction @{ Action = 'external-isolation'; Detail = 'Machine isolée via le portail Defender' }

        $Entry = @($Case.ActionLog | Where-Object { $_.Action -eq 'external-isolation' })
        $Entry.Count | Should -Be 1
        $Entry[0].Analyst | Should -Be 'analyste@example.test'
    }

    It 'truncates a runaway log at 200 entries and says so in the log itself' {
        for ($i = 1; $i -le 210; $i++) {
            $null = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'a' -CaseId $script:Case.CaseId -LogAction @{ Action = "note-$i"; Detail = '' }
        }
        $Case = @(Get-PSITSocCase -TenantFilter 'contoso.test' -CaseId $script:Case.CaseId)[0]

        @($Case.ActionLog).Count | Should -BeLessOrEqual 200
        @($Case.ActionLog | Where-Object { $_.Action -eq 'log-truncated' }).Count | Should -BeGreaterThan 0
    }
}

Describe 'Get-PSITSocCase' {
    BeforeEach {
        Reset-Store
        Enable-StoreMocks
        Mock -CommandName Write-LogMessage -MockWith { }
    }

    It 'returns an empty array rather than nothing when no case exists' {
        $Result = Get-PSITSocCase -TenantFilter 'contoso.test'
        @($Result).Count | Should -Be 0
    }

    It 'filters by status and source in memory' {
        $null = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'a' -Source 'extsoc' -TypeId 1 -Title 'Connexion Suisse'
        $Tp = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'a' -Source 'xdr' -TypeId 15 -Title 'Infostealer'
        $null = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'a' -CaseId $Tp.CaseId -Verdict 'true-positive'

        @(Get-PSITSocCase -TenantFilter 'contoso.test' -Source 'extsoc').Count | Should -Be 1
        @(Get-PSITSocCase -TenantFilter 'contoso.test' -Status 'qualified-tp').Count | Should -Be 1
        @(Get-PSITSocCase -TenantFilter 'contoso.test' -Status 'qualified-tp')[0].Title | Should -Be 'Infostealer'
    }

    It 'a row whose JSON field is corrupt still renders instead of sinking the queue' {
        $script:Store['contoso.test|PSIT-SOC-20260824-DEAD'] = [pscustomobject]@{
            PartitionKey = 'contoso.test'
            RowKey       = 'PSIT-SOC-20260824-DEAD'
            Source       = 'extsoc'
            TypeId       = '1'
            Status       = 'new'
            Title        = 'Cas au JSON abîmé'
            ActionLog    = '{not json'
            Entities     = '{not json'
            UpdatedUtc   = '2026-08-24T10:00:00Z'
        }

        $Result = @(Get-PSITSocCase -TenantFilter 'contoso.test')
        $Result.Count | Should -Be 1
        $Result[0].Title | Should -Be 'Cas au JSON abîmé'
        @($Result[0].ActionLog).Count | Should -Be 0
    }

    It 'carries the tenant on a Tenant property, which the allowed-tenant filter relies on' {
        $null = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'a' -Source 'manual' -TypeId 4 -Title 'Rôle ajouté'
        @(Get-PSITSocCase)[0].Tenant | Should -Be 'contoso.test'
    }
}

Describe 'Set-PSITSocCase assignment' {
    # Who is on a case and who last touched it are different facts. Conflating them would show a
    # case as taken by whoever added the most recent note, which is how two analysts end up each
    # believing the other is handling it.

    BeforeEach {
        $script:Written = [System.Collections.Generic.List[object]]::new()
        Mock -CommandName Add-CIPPAzDataTableEntity -MockWith { $script:Written.Add($Entity) }
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith { $null }
    }

    It 'records who took the case' {
        $null = Set-PSITSocCase -TenantFilter 'contoso.test' -Analyst 'first@example.test' -Source 'manual' -TypeId 2 -Title 'x' -AssignedTo 'first@example.test'
        $script:Written[0].AssignedTo | Should -Be 'first@example.test'
    }

    It 'leaves the assignment alone when an update does not mention it' {
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith {
            [pscustomobject]@{
                PartitionKey = 'contoso.test'; RowKey = 'PSIT-SOC-1'; CaseId = 'PSIT-SOC-1'
                Tenant = 'contoso.test'; Source = 'manual'; TypeId = '2'; Title = 'x'
                Severity = 'P3'; Status = 'investigating'; AssignedTo = 'first@example.test'
                CreatedUtc = '2026-08-25T09:00:00Z'; CreatedBy = 'first@example.test'
            }
        }

        # A second analyst adding a note must not appear to have taken the case.
        $null = Set-PSITSocCase -TenantFilter 'contoso.test' -CaseId 'PSIT-SOC-1' -Analyst 'second@example.test' -LogAction @{ Action = 'note'; Detail = 'vu' }

        $script:Written[0].AssignedTo | Should -Be 'first@example.test'
        $script:Written[0].UpdatedBy | Should -Be 'second@example.test'
    }

    It 'releases the case on an empty assignment rather than ignoring it' {
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith {
            [pscustomobject]@{
                PartitionKey = 'contoso.test'; RowKey = 'PSIT-SOC-1'; CaseId = 'PSIT-SOC-1'
                Tenant = 'contoso.test'; Source = 'manual'; TypeId = '2'; Title = 'x'
                Severity = 'P3'; Status = 'investigating'; AssignedTo = 'first@example.test'
                CreatedUtc = '2026-08-25T09:00:00Z'; CreatedBy = 'first@example.test'
            }
        }

        $null = Set-PSITSocCase -TenantFilter 'contoso.test' -CaseId 'PSIT-SOC-1' -Analyst 'first@example.test' -AssignedTo ''

        $script:Written[0].AssignedTo | Should -BeNullOrEmpty
    }
}
