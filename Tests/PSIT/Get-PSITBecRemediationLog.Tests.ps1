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
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/PSIT/Close-PSITBecIncident.ps1')

    function Get-CippTable { param($tablename) @{ Table = $tablename } }
    function Get-CIPPAzDataTableEntity { param($Table, $Filter, $Property) }
    function Add-CIPPAzDataTableEntity { param($Table, $Entity, [switch]$Force) }
    function Remove-AzDataTableEntity { param($Context, $Entity, [switch]$Force) }
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

# Regression guard for the incident save. The panel sends '' for every field the analyst has not
# filled, and these parameters carry a ValidateSet: passing the blank through is what made a whole
# save fail because one optional field was untouched. The endpoint must omit blanks, and these
# tests pin the constraint it is protecting against, so relaxing the guard fails loudly here.
Describe 'Set-PSITBecIncident rejects blanks on its validated fields' {
    BeforeEach {
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith { $null }
        Mock -CommandName Add-CIPPAzDataTableEntity -MockWith { }
    }

    It 'refuses an empty string on every validated field' {
        foreach ($Field in @('EffectDescription', 'Status', 'MailReadStatus', 'Tlp')) {
            {
                $Parameters = @{
                    TenantFilter = 'contoso.test'
                    UserId       = 'user-guid'
                    Analyst      = 'analyste@example.test'
                    $Field       = ''
                }
                Set-PSITBecIncident @Parameters
            } | Should -Throw
        }
    }

    It 'saves when those fields are simply not sent, which is what omitting a blank does' {
        # Asserting on what was written rather than on what is returned: the function re-reads the
        # record through Get-PSITBecIncident, which the mocked table answers empty.
        $script:Written = $null
        Mock -CommandName Add-CIPPAzDataTableEntity -MockWith { $script:Written = $Entity }

        $null = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'user-guid' -Analyst 'analyste@example.test' -AutotaskTicket 'T20260820.0042'

        $script:Written.AutotaskTicket | Should -Be 'T20260820.0042'
        $script:Written.Reference | Should -Match '^PSIT-BEC-'
    }
}

Describe 'Get-PSITBecRemediationLog' {
    BeforeEach {
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith {
            @(
                New-LogRow 'ExecBECRemediate' 'Reset password for p.martin@contoso.test' 'analyste@example.test' 'Info' '2026-08-20T13:00:00Z'
                New-LogRow 'ExecBECRemediate' 'Revoked sessions for p.martin@contoso.test' 'analyste@example.test' 'Info' '2026-08-20T13:01:00Z'
                New-LogRow 'ExecBECRemediate' 'Successfully disabled rule: Facturation for p.martin@contoso.test' 'analyste@example.test' 'Info' '2026-08-20T13:02:00Z'
                New-LogRow 'ExecBECRemediate' 'Could not disable rule for p.martin@contoso.test: access denied' 'analyste@example.test' 'Error' '2026-08-20T13:03:00Z'
                # Same endpoint, different mailbox: must not be attributed to this incident.
                New-LogRow 'ExecBECRemediate' 'Reset password for someone.else@contoso.test' 'analyste@example.test' 'Info' '2026-08-20T13:04:00Z'
                # An unrelated endpoint that mentions the mailbox: not remediation.
                New-LogRow 'ListUsers' 'Listed users including p.martin@contoso.test' 'analyste@example.test' 'Info' '2026-08-20T13:05:00Z'
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
        ($Result.ActionsPerformed | Where-Object { $_.Action -eq 'PasswordReset' }).Operator | Should -Be 'analyste@example.test'
    }

    It 'returns empty rather than throwing when the log holds nothing' {
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith { @() }
        $Result = Get-PSITBecRemediationLog -TenantFilter 'contoso.test' -UserPrincipalName 'p.martin@contoso.test' -SinceUtc ([datetime]'2026-08-20T00:00:00Z')

        @($Result.Entries).Count | Should -Be 0
        @($Result.ActionsPerformed).Count | Should -Be 0
    }

    It 'reads the Remediate User run under the casing the front actually sends' {
        # The upstream front calls /api/execBecRemediate, so every step logs under that exact
        # casing, and the endpoint's summary line is hardcoded to 'BECRemediate'. The table filter
        # compares case-sensitively: an allowlist carrying only 'ExecBECRemediate' made the whole
        # run invisible, and a freshly remediated mailbox read 'non attestee' on every action.
        # Messages below are verbatim from the helpers the endpoint calls.
        $script:SeenFilter = ''
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith {
            $script:SeenFilter = $Filter
            @(
                New-LogRow 'execBecRemediate' 'Successfully reset the password for Cedric REY, c.exemple@contoso.test. User must change password is set to True' 'analyste@example.test' 'Info' '2026-08-31T10:30:00Z'
                New-LogRow 'execBecRemediate' 'Successfully set account enabled state to False for c.exemple@contoso.test' 'analyste@example.test' 'Info' '2026-08-31T10:30:05Z'
                New-LogRow 'execBecRemediate' 'Successfully revoked sessions for c.exemple@contoso.test' 'analyste@example.test' 'Info' '2026-08-31T10:30:10Z'
                New-LogRow 'execBecRemediate' 'Successfully removed MFA methods (microsoftAuthenticator) for user c.exemple@contoso.test. User must supply MFA at next logon' 'analyste@example.test' 'Info' '2026-08-31T10:30:15Z'
                New-LogRow 'execBecRemediate' 'Retrieved 3 total rules for c.exemple@contoso.test' 'analyste@example.test' 'Info' '2026-08-31T10:30:20Z'
                New-LogRow 'execBecRemediate' "Successfully set OneDrive sharing to 'Disabled' for c.exemple@contoso.test (https://contoso-my.sharepoint.com/personal/c)" 'analyste@example.test' 'Info' '2026-08-31T10:30:25Z'
                New-LogRow 'BECRemediate' 'Executed Remediation for c.exemple@contoso.test' 'analyste@example.test' 'Info' '2026-08-31T10:30:30Z'
            )
        }

        $Result = Get-PSITBecRemediationLog -TenantFilter 'contoso.test' -UserPrincipalName 'c.exemple@contoso.test' -SinceUtc ([datetime]'2026-08-31T00:00:00Z')
        $Actions = @($Result.ActionsPerformed | Select-Object -ExpandProperty Action)

        # The mock cannot exercise the table service's case sensitivity, so the filter string
        # itself is pinned: both spellings must be asked for.
        $script:SeenFilter | Should -Match "API eq 'execBecRemediate'"
        $script:SeenFilter | Should -Match "API eq 'BECRemediate'"

        $Actions | Should -Contain 'PasswordReset'
        $Actions | Should -Contain 'SignInBlocked'
        $Actions | Should -Contain 'SessionsRevoked'
        $Actions | Should -Contain 'MfaMethodsRemoved'
        $Actions | Should -Contain 'InboxRulesDisabled'
        $Actions | Should -Contain 'SharingDisabled'
    }

    It 'never attests a sign-in block from an unblock' {
        # 'account enabled state to True' is the mirror gesture: re-enabling the account.
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith {
            @(New-LogRow 'execBecRemediate' 'Successfully set account enabled state to True for c.exemple@contoso.test' 'analyste@example.test' 'Info' '2026-08-31T11:00:00Z')
        }

        $Result = Get-PSITBecRemediationLog -TenantFilter 'contoso.test' -UserPrincipalName 'c.exemple@contoso.test' -SinceUtc ([datetime]'2026-08-31T00:00:00Z')

        @($Result.ActionsPerformed | Where-Object { $_.Action -eq 'SignInBlocked' }).Count | Should -Be 0
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
        $First = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -UserPrincipalName 'p.martin@contoso.test' -Analyst 'analyste' -Status 'ongoing'
        $First.Reference | Should -Match '^PSIT-BEC-\d{8}-[0-9A-F]{4}$'

        $Second = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 'analyste' -Status 'contained'
        $Second.Reference | Should -Be $First.Reference
        $Second.Status | Should -Be 'contained'
    }

    It 'dates the reference on the detection when the first save carries one' {
        $Incident = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u2' -Analyst 'analyste' -DetectedUtc '2026-07-03T08:00:00Z'
        $Incident.Reference | Should -Match '^PSIT-BEC-20260703-[0-9A-F]{4}$'

        # And never moves afterwards, even once the detection date is corrected.
        $Updated = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u2' -Analyst 'analyste' -DetectedUtc '2026-08-01T08:00:00Z'
        $Updated.Reference | Should -Be $Incident.Reference
    }

    It 'does not wipe a field that a later save leaves out' {
        $null = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 'analyste' -LikelyConsequences 'Détournement de paiement' -DataCategories @('Données bancaires ou financières')
        $Updated = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 'a.other' -Status 'contained'

        $Updated.LikelyConsequences | Should -Be 'Détournement de paiement'
        $Updated.DataCategories | Should -Contain 'Données bancaires ou financières'
        $Updated.UpdatedBy | Should -Be 'a.other'
    }

    It 'round-trips the Autotask ticket, which is the reference both reports quote' {
        $Saved = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 'analyste' -AutotaskTicket 'T20260820.0042'
        $Saved.AutotaskTicket | Should -Be 'T20260820.0042'

        # A later save that only touches the status must not lose the business reference.
        $Updated = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 'analyste' -Status 'contained'
        $Updated.AutotaskTicket | Should -Be 'T20260820.0042'
    }

    It 'records the handover of the report, which is evidence in its own right' {
        $Saved = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 'analyste' `
            -DeliveredTo 'Direction financière' -DeliveredUtc '2026-08-21T09:00:00Z' `
            -DeliveryChannel 'courriel' -AcknowledgedBy 'DAF' -AcknowledgedUtc '2026-08-21T10:30:00Z'

        $Saved.DeliveredTo | Should -Be 'Direction financière'
        $Saved.DeliveredUtc | Should -Be '2026-08-21T09:00:00Z'
        $Saved.DeliveryChannel | Should -Be 'courriel'
        $Saved.AcknowledgedBy | Should -Be 'DAF'
        $Saved.AcknowledgedUtc | Should -Be '2026-08-21T10:30:00Z'
    }

    It 'refuses an unparseable acknowledgement date rather than storing rubbish' {
        { Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 'analyste' -AcknowledgedUtc 'la semaine derniere' } |
            Should -Throw '*not a valid date*'
    }

    It 'marks a new case TLP:AMBER+STRICT and keeps a deliberate widening' {
        $Created = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u4' -Analyst 'analyste'
        $Created.Tlp | Should -Be 'TLP:AMBER+STRICT'

        $Widened = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u4' -Analyst 'analyste' -Tlp 'TLP:GREEN'
        $Widened.Tlp | Should -Be 'TLP:GREEN'

        # A later save that says nothing about the marking must not pull it back to the default.
        $Untouched = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u4' -Analyst 'analyste' -Status 'contained'
        $Untouched.Tlp | Should -Be 'TLP:GREEN'
    }

    It 'refuses a marking or an effect outside the enumeration' {
        { Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u5' -Analyst 'analyste' -Tlp 'TLP:ORANGE' } |
            Should -Throw
        { Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u5' -Analyst 'analyste' -EffectDescription 'spam massif' } |
            Should -Throw
    }

    It 'refuses a channel outside the enumeration, on the field and inside the list' {
        # The constraint cannot live in the panel alone: a value posted straight to the endpoint
        # would otherwise be printed in a client report.
        { Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u6' -Analyst 'analyste' -DeliveryChannel 'Pigeon voyageur' } |
            Should -Throw '*must be one of*'
        { Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u6' -Analyst 'analyste' -ThirdPartiesNotified @(@{ Name = 'Banque'; Channel = 'Pigeon voyageur' }) } |
            Should -Throw '*ThirdPartiesNotified.Channel*'

        $Valid = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u6' -Analyst 'analyste' -DeliveryChannel 'courriel' -ThirdPartiesNotified @(@{ Name = 'Banque'; Channel = 'telephone' })
        $Valid.DeliveryChannel | Should -Be 'courriel'
    }

    It 'keeps the related tickets and the free-text effect' {
        $Incident = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u7' -Analyst 'analyste' `
            -EffectDescription 'other' -EffectDescriptionOther 'exfiltration vers un partage tiers' `
            -RelatedTickets @('T20260820.0014', 'T20260821.0002')

        $Incident.EffectDescription | Should -Be 'other'
        $Incident.EffectDescriptionOther | Should -Be 'exfiltration vers un partage tiers'
        $Incident.RelatedTickets | Should -Contain 'T20260821.0002'
    }

    It 'normalises timestamps to UTC' {
        $Incident = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 'analyste' -DetectedUtc '2026-08-20T11:00:00+02:00'
        $Incident.DetectedUtc | Should -Be '2026-08-20T09:00:00Z'
    }

    It 'refuses a date it cannot parse rather than storing rubbish' {
        { Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 'analyste' -DetectedUtc 'hier soir' } | Should -Throw '*not a valid date*'
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

Describe 'Close-PSITBecIncident' {
    BeforeEach {
        # One store per table, keyed by RowKey, so archiving and removal are observable.
        $script:Store = @{ PSITBecIncidents = @{}; PSITBecTriage = @{}; PSITBecCollections = @{}; cachebec = @{} }
        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName Get-CippTable -MockWith { param($tablename) @{ Context = $tablename; Table = $tablename } }
        Mock -CommandName Get-CIPPAzDataTableEntity -MockWith {
            param($Context, $Table, $Filter, $Property)
            $Name = if ($Context) { $Context } else { $Table }
            $Rows = $script:Store[$Name]
            if ($null -eq $Rows) { return $null }
            if ($Filter -match "RowKey eq '([^']+)'") { return $Rows[$Matches[1]] }
            if ($Filter -match "RowKey ge '([^']+)' and RowKey le '([^']+)'") {
                $Low = $Matches[1]; $High = $Matches[2]
                # Ordinal, like the table service: PowerShell's -ge/-le are culture-aware, and in
                # that comparison '~' sorts before a letter, so the range would silently miss every
                # archived row. Azure compares UTF-16 code units.
                return @($Rows.Keys | Where-Object {
                        [string]::CompareOrdinal($_, $Low) -ge 0 -and [string]::CompareOrdinal($_, $High) -le 0
                    } | ForEach-Object { $Rows[$_] })
            }
            return $null
        }
        Mock -CommandName Add-CIPPAzDataTableEntity -MockWith {
            param($Context, $Table, $Entity, [switch]$Force)
            $Name = if ($Context) { $Context } else { $Table }
            $script:Store[$Name][[string]$Entity.RowKey] = [pscustomobject]$Entity
        }
        Mock -CommandName Remove-AzDataTableEntity -MockWith {
            param($Context, $Entity, [switch]$Force)
            $script:Store[$Context].Remove([string]$Entity.RowKey)
        }
    }

    It 'archives the case and frees the slot, so the next save opens a new one' {
        $First = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 'analyste' -DetectedUtc '2026-08-20T09:00:00Z' -LikelyConsequences 'Détournement de paiement'
        $Closure = Close-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 'analyste' -ClosureNote 'Confinée et validée par le client'

        $Closure.Closed | Should -BeTrue
        $Closure.Reference | Should -Be $First.Reference

        # The live slot is empty: nothing of the first case can be inherited.
        $Fresh = Get-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1'
        $Fresh.Exists | Should -BeFalse
        $Fresh.LikelyConsequences | Should -BeNullOrEmpty

        $Second = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 'analyste' -DetectedUtc '2026-11-02T07:00:00Z'
        $Second.Reference | Should -Not -Be $First.Reference
        $Second.Reference | Should -Match '^PSIT-BEC-20261102-'
        $Second.LikelyConsequences | Should -BeNullOrEmpty
    }

    It 'keeps the closed case readable, because a repeat compromise is a finding' {
        $First = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 'analyste' -DetectedUtc '2026-08-20T09:00:00Z' -Status 'contained'
        $null = Close-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 'analyste'
        $null = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 'analyste' -DetectedUtc '2026-11-02T07:00:00Z'

        $Current = Get-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1'
        $Current.RepeatOffence | Should -BeTrue
        @($Current.PreviousCases).Count | Should -Be 1
        $Current.PreviousCases[0].Reference | Should -Be $First.Reference
        $Current.PreviousCases[0].ClosedBy | Should -Be 'analyste'
    }

    It 'archives the determinations with their case, so they cannot silence a later signal' {
        $null = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 'analyste'
        $script:Store['PSITBecTriage']['u1'] = [pscustomobject]@{
            PartitionKey   = 'contoso.test'
            RowKey         = 'u1'
            Determinations = '[{"SignalId":"signin-ip:203.0.113.42","Verdict":"expected"}]'
        }

        $Closure = Close-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 'analyste'

        $Closure.ArchivedDeterminations | Should -Be 1
        $script:Store['PSITBecTriage'].ContainsKey('u1') | Should -BeFalse
        $script:Store['PSITBecTriage'].ContainsKey("u1_$($Closure.Reference)") | Should -BeTrue
    }

    It 'archives the collection, which upstream would otherwise overwrite on the next run' {
        $null = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 'analyste'
        $script:Store['cachebec']['u1'] = [pscustomobject]@{
            PartitionKey = 'bec'
            RowKey       = 'u1'
            Results      = '{"ExtractedAt":"2026-08-20T10:32:00Z","SentMessages":[]}'
        }

        $Closure = Close-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u1' -Analyst 'analyste'

        $Closure.CollectionArchived | Should -BeTrue
        $Archived = $script:Store['PSITBecCollections']["u1_$($Closure.Reference)"]
        $Archived.Collection | Should -Match 'SentMessages'
        $Archived.CollectedUtc | Should -Be '2026-08-20T10:32:00Z'
    }

    It 'closes the case even when there is no collection left to archive' {
        $null = Set-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u3' -Analyst 'analyste'
        $Closure = Close-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'u3' -Analyst 'analyste'

        $Closure.Closed | Should -BeTrue
        $Closure.CollectionArchived | Should -BeFalse
    }

    It 'refuses to close a mailbox that has no open case' {
        $Closure = Close-PSITBecIncident -TenantFilter 'contoso.test' -UserId 'never-seen' -Analyst 'analyste'
        $Closure.Closed | Should -BeFalse
        $Closure.Reason | Should -Match 'nothing to close'
    }
}
