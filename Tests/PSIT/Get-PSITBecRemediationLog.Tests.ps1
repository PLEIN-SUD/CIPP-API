# Pester tests for the incident-record side: reading back what CIPP actually did to a compromised
# mailbox (Get-PSITBecRemediationLog) and storing the facts only an analyst can supply
# (Set-PSITBecIncident / Get-PSITBecIncident).
#
# The remediation trail is the section an insurer or a DPO reads closely, so the tests pin the two
# properties that make it trustworthy: an entry counts only if it comes from a remediation endpoint
# AND names the mailbox, and the action label is derived from the logged message rather than assumed.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Get-PSITBecRemediationLog.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Get-PSITBecIncident.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Set-PSITBecIncident.ps1')

    function Get-CippTable { param($tablename) @{ Table = $tablename } }
    function Get-CIPPAzDataTableEntity { param($Table, $Filter, $Property) }
    function Add-CIPPAzDataTableEntity { param($Table, $Entity, [switch]$Force) }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $headers, $LogData) }

    function New-LogRow {
        param($Api, $Message, $Username, $Severity, $Timestamp)
        [pscustomobject]@{
            API       = $Api
            Message   = $Message
            Username  = $Username
            Severity  = $Severity ?? 'Info'
            Tenant    = 'contoso.test'
            Timestamp = [datetimeoffset]::Parse(($Timestamp ?? '2026-08-20T13:00:00Z'))
        }
    }
}

Describe 'Get-PSITBecRemediationLog' {
    BeforeEach {
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith {
            @(
                New-LogRow 'ExecBECRemediate' 'Reset password for p.martin@contoso.test' 's.miro@pleinsudit.com' 'Info' '2026-08-20T13:00:00Z'
                New-LogRow 'ExecBECRemediate' 'Revoked sessions for p.martin@contoso.test' 's.miro@pleinsudit.com' 'Info' '2026-08-20T13:01:00Z'
                New-LogRow 'ExecBECRemediate' 'Successfully disabled rule: Facturation for p.martin@contoso.test' 's.miro@pleinsudit.com' 'Info' '2026-08-20T13:02:00Z'
                New-LogRow 'ExecBECRemediate' 'Could not disable rule for p.martin@contoso.test: access denied' 's.miro@pleinsudit.com' 'Error' '2026-08-20T13:03:00Z'
                # Same endpoint, different mailbox: must not be attributed to this incident.
                New-LogRow 'ExecBECRemediate' 'Reset password for someone.else@contoso.test' 's.miro@pleinsudit.com' 'Info' '2026-08-20T13:04:00Z'
                # An unrelated endpoint that mentions the mailbox: not remediation.
                New-LogRow 'ListUsers' 'Listed users including p.martin@contoso.test' 's.miro@pleinsudit.com' 'Info' '2026-08-20T13:05:00Z'
            )
        }
    }

    It 'keeps only remediation entries that name the mailbox' {
        $Result = Get-PSITBecRemediationLog -TenantFilter 'contoso.test' -UserPrincipalName 'p.martin@contoso.test' -SinceUtc ([datetime]'2026-08-20T00:00:00Z')

        @($Result.Entries).Count | Should -BeGreaterThan 0
        @($Result.Entries | Where-Object { $_.Message -like '*someone.else*' }).Count | Should -Be 0
        @($Result.Entries | Where-Object { $_.Api -eq 'ListUsers' }).Count | Should -Be 0
    }

    It 'maps log messages to the canonical containment actions' {
        $Result = Get-PSITBecRemediationLog -TenantFilter 'contoso.test' -UserPrincipalName 'p.martin@contoso.test' -SinceUtc ([datetime]'2026-08-20T00:00:00Z')
        $Actions = @($Result.ActionsPerformed | Select-Object -ExpandProperty Action)

        $Actions | Should -Contain 'PasswordReset'
        $Actions | Should -Contain 'SessionsRevoked'
        $Actions | Should -Contain 'InboxRulesDisabled'
    }

    It 'surfaces a failure rather than reporting the action as clean' {
        $Result = Get-PSITBecRemediationLog -TenantFilter 'contoso.test' -UserPrincipalName 'p.martin@contoso.test' -SinceUtc ([datetime]'2026-08-20T00:00:00Z')
        $Rules = $Result.ActionsPerformed | Where-Object { $_.Action -eq 'InboxRulesDisabled' }

        $Rules.HasFailure | Should -BeTrue
    }

    It 'records the operator, which is what makes the section an attestation' {
        $Result = Get-PSITBecRemediationLog -TenantFilter 'contoso.test' -UserPrincipalName 'p.martin@contoso.test' -SinceUtc ([datetime]'2026-08-20T00:00:00Z')
        ($Result.ActionsPerformed | Where-Object { $_.Action -eq 'PasswordReset' }).Operator | Should -Be 's.miro@pleinsudit.com'
    }

    It 'returns empty rather than throwing when the log holds nothing' {
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith { @() }
        $Result = Get-PSITBecRemediationLog -TenantFilter 'contoso.test' -UserPrincipalName 'p.martin@contoso.test' -SinceUtc ([datetime]'2026-08-20T00:00:00Z')

        @($Result.Entries).Count | Should -Be 0
        @($Result.ActionsPerformed).Count | Should -Be 0
    }

    It 'never looks further back than the log retention makes meaningful' {
        $Result = Get-PSITBecRemediationLog -TenantFilter 'contoso.test' -UserPrincipalName 'p.martin@contoso.test' -SinceUtc ([datetime]::UtcNow.AddDays(-400))
        $WindowStart = [datetime]::Parse($Result.WindowStartUtc)

        $WindowStart | Should -BeGreaterThan ([datetime]::UtcNow.AddDays(-91))
    }
}

Describe 'Set-PSITBecIncident' {
    BeforeEach {
        $script:Store = @{}
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith {
            param($Table, $Filter, $Property)
            if ($Filter -match "RowKey eq '([^']+)'") { return $script:Store[$Matches[1]] }
            return $null
        }
        Mock -CommandName Add-CIPPAzDataTableEntity -MockWith {
            param($Table, $Entity, [switch]$Force)
            $script:Store[$Entity.RowKey] = [pscustomobject]$Entity
        }
    }

    It 'generates a stable, readable reference on first save and keeps it afterwards' {
        $First = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -UserPrincipalName 'p.martin@contoso.test' -Analyst 's.miro' -Status 'ongoing'
        $First.Reference | Should -Match '^PSIT-BEC-\d{8}-[0-9A-F]{4}$'

        $Second = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 's.miro' -Status 'contained'
        $Second.Reference | Should -Be $First.Reference
        $Second.Status | Should -Be 'contained'
    }

    It 'dates the reference on the detection when the first save carries one' {
        $Incident = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u2' -Analyst 's.miro' -DetectedUtc '2026-07-03T08:00:00Z'
        $Incident.Reference | Should -Match '^PSIT-BEC-20260703-[0-9A-F]{4}$'

        # And never moves afterwards, even once the detection date is corrected.
        $Updated = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u2' -Analyst 's.miro' -DetectedUtc '2026-08-01T08:00:00Z'
        $Updated.Reference | Should -Be $Incident.Reference
    }

    It 'does not wipe a field that a later save leaves out' {
        $null = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 's.miro' -LikelyConsequences 'Détournement de paiement' -DataCategories @('Données bancaires ou financières')
        $Updated = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 'a.other' -Status 'contained'

        $Updated.LikelyConsequences | Should -Be 'Détournement de paiement'
        $Updated.DataCategories | Should -Contain 'Données bancaires ou financières'
        $Updated.UpdatedBy | Should -Be 'a.other'
    }

    It 'round-trips the Autotask ticket, which is the reference both reports quote' {
        $Saved = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 's.miro' -AutotaskTicket 'T20260820.0042'
        $Saved.AutotaskTicket | Should -Be 'T20260820.0042'

        # A later save that only touches the status must not lose the business reference.
        $Updated = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 's.miro' -Status 'contained'
        $Updated.AutotaskTicket | Should -Be 'T20260820.0042'
    }

    It 'records the handover of the report, which is evidence in its own right' {
        $Saved = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 's.miro' `
            -DeliveredTo 'Direction financière' -DeliveredUtc '2026-08-21T09:00:00Z' `
            -DeliveryChannel 'courriel' -AcknowledgedBy 'DAF' -AcknowledgedUtc '2026-08-21T10:30:00Z'

        $Saved.DeliveredTo | Should -Be 'Direction financière'
        $Saved.DeliveredUtc | Should -Be '2026-08-21T09:00:00Z'
        $Saved.DeliveryChannel | Should -Be 'courriel'
        $Saved.AcknowledgedBy | Should -Be 'DAF'
        $Saved.AcknowledgedUtc | Should -Be '2026-08-21T10:30:00Z'
    }

    It 'refuses an unparseable acknowledgement date rather than storing rubbish' {
        { Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 's.miro' -AcknowledgedUtc 'la semaine derniere' } |
            Should -Throw '*not a valid date*'
    }

    It 'normalises timestamps to UTC' {
        $Incident = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 's.miro' -DetectedUtc '2026-08-20T11:00:00+02:00'
        $Incident.DetectedUtc | Should -Be '2026-08-20T09:00:00Z'
    }

    It 'refuses a date it cannot parse rather than storing rubbish' {
        { Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 's.miro' -DetectedUtc 'hier soir' } | Should -Throw '*not a valid date*'
    }

    It 'keeps the creator distinct from the last editor' {
        $null = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 'first.analyst'
        $Updated = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 'second.analyst'

        $Updated.CreatedBy | Should -Be 'first.analyst'
        $Updated.UpdatedBy | Should -Be 'second.analyst'
    }

    It 'reports a mailbox with no incident as not existing' {
        $Empty = Get-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'never-seen'
        $Empty.Exists | Should -BeFalse
        @($Empty.DataCategories).Count | Should -Be 0
    }
}
