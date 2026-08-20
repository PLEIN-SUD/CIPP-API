# Pester tests for the PSIT shared/resource mailbox exclusion used by the inactivity alerts:
#   Get-PSITNonUserMailboxIndex builds the index from the cached Mailboxes dataset,
#   Test-PSITNonUserMailbox matches a Graph user against it,
#   Get-CIPPAlertInactiveUsers skips the matched users when the alert opts in.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $IndexPath = Join-Path $RepoRoot 'Modules/CIPPCore/Public/Get-PSITNonUserMailboxIndex.ps1'
    $TestPath = Join-Path $RepoRoot 'Modules/CIPPCore/Public/Test-PSITNonUserMailbox.ps1'
    $AlertPath = Join-Path $RepoRoot 'Modules/CIPPAlerts/Public/Alerts/Get-CIPPAlertInactiveUsers.ps1'

    function Get-CIPPDbItem { param($TenantFilter, $Type, [switch]$CountsOnly) }
    function Write-AlertTrace { param($cmdletName, $tenantFilter, $data) }
    function Write-LogMessage { param($API, $tenant, $message, $sev, $LogData) }
    function Get-CippException { param($Exception) [pscustomobject]@{ NormalizedError = "$Exception" } }
    function New-GraphGetRequest { param($uri, $tenantid, $scope) }

    # Cache rows are stored by Add-CIPPDbItem as RowKey "<Type>-<id>" with Data = compressed JSON.
    function New-MailboxItem {
        param($Id, $Upn, $RecipientTypeDetails, $PrimarySmtpAddress)
        [pscustomobject]@{
            RowKey = "Mailboxes-$Id"
            Data   = (@{
                    ExternalDirectoryObjectId = $Id
                    UPN                       = $Upn
                    primarySmtpAddress        = if ($PrimarySmtpAddress) { $PrimarySmtpAddress } else { $Upn }
                    recipientTypeDetails      = $RecipientTypeDetails
                } | ConvertTo-Json -Compress)
        }
    }

    . $IndexPath
    . $TestPath
    . $AlertPath
}

Describe 'Get-PSITNonUserMailboxIndex' {
    BeforeEach {
        Mock -CommandName Write-LogMessage -MockWith { }

        Mock -CommandName Get-CIPPDbItem -MockWith {
            @(
                New-MailboxItem 'id-user' 'real.person@contoso.test' 'UserMailbox'
                New-MailboxItem 'id-shared' 'accueil@contoso.test' 'SharedMailbox'
                New-MailboxItem 'id-room' 'salle-1@contoso.test' 'RoomMailbox'
                New-MailboxItem 'id-equip' 'projecteur@contoso.test' 'EquipmentMailbox'
                [pscustomobject]@{ RowKey = 'Mailboxes-Count'; Data = '{"count":4}' }
            )
        }
    }

    It 'indexes shared and resource mailboxes on every identifier they carry' {
        $Index = Get-PSITNonUserMailboxIndex -TenantFilter 'contoso.onmicrosoft.com'

        $Index.Contains('id-shared') | Should -BeTrue
        $Index.Contains('accueil@contoso.test') | Should -BeTrue
        $Index.Contains('id-room') | Should -BeTrue
        $Index.Contains('id-equip') | Should -BeTrue
    }

    It 'leaves real user mailboxes out of the index' {
        $Index = Get-PSITNonUserMailboxIndex -TenantFilter 'contoso.onmicrosoft.com'

        $Index.Contains('id-user') | Should -BeFalse
        $Index.Contains('real.person@contoso.test') | Should -BeFalse
    }

    It 'ignores the Mailboxes-Count bookkeeping row' {
        $Index = Get-PSITNonUserMailboxIndex -TenantFilter 'contoso.onmicrosoft.com'

        $Index.Count | Should -Be 6   # 3 non-user mailboxes x (id + upn), smtp equals the upn here
    }

    It 'matches identifiers case-insensitively, since UPNs are not case sensitive' {
        $Index = Get-PSITNonUserMailboxIndex -TenantFilter 'contoso.onmicrosoft.com'

        $Index.Contains('Accueil@Contoso.Test') | Should -BeTrue
    }

    It 'honours a narrowed recipient type list' {
        $Index = Get-PSITNonUserMailboxIndex -TenantFilter 'contoso.onmicrosoft.com' -RecipientTypeDetails 'SharedMailbox'

        $Index.Contains('id-shared') | Should -BeTrue
        $Index.Contains('id-room') | Should -BeFalse
    }

    It 'returns null and warns when the tenant has no cached mailboxes, so callers do not filter blindly' {
        Mock -CommandName Get-CIPPDbItem -MockWith { @() }

        $Index = Get-PSITNonUserMailboxIndex -TenantFilter 'contoso.onmicrosoft.com'

        $Index | Should -BeNullOrEmpty
        Should -Invoke Write-LogMessage -Times 1 -ParameterFilter { $sev -eq 'Warning' }
    }

    It 'returns null and warns when the cache read throws' {
        Mock -CommandName Get-CIPPDbItem -MockWith { throw 'table not found' }

        $Index = Get-PSITNonUserMailboxIndex -TenantFilter 'contoso.onmicrosoft.com'

        $Index | Should -BeNullOrEmpty
        Should -Invoke Write-LogMessage -Times 1 -ParameterFilter { $sev -eq 'Warning' }
    }

    It 'returns an empty index when the tenant simply has no shared mailbox' {
        Mock -CommandName Get-CIPPDbItem -MockWith { @(New-MailboxItem 'id-user' 'real.person@contoso.test' 'UserMailbox') }

        $Index = Get-PSITNonUserMailboxIndex -TenantFilter 'contoso.onmicrosoft.com'

        # An empty index must stay an index: callers tell 'nothing to exclude' from 'no cache'
        # by testing for $null, so the set must survive the return without being unrolled.
        $Index -is [System.Collections.Generic.HashSet[string]] | Should -BeTrue
        $Index.Count | Should -Be 0
    }
}

Describe 'Test-PSITNonUserMailbox' {
    BeforeAll {
        $script:Index = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $null = $script:Index.Add('id-shared')
        $null = $script:Index.Add('accueil@contoso.test')
    }

    It 'matches on the object id' {
        Test-PSITNonUserMailbox -Index $script:Index -User ([pscustomobject]@{ id = 'id-shared'; UserPrincipalName = 'other@contoso.test' }) | Should -BeTrue
    }

    It 'matches on the UPN when the id is unknown' {
        Test-PSITNonUserMailbox -Index $script:Index -User ([pscustomobject]@{ id = 'id-unknown'; UserPrincipalName = 'accueil@contoso.test' }) | Should -BeTrue
    }

    It 'matches on the mail address when neither id nor UPN is indexed' {
        Test-PSITNonUserMailbox -Index $script:Index -User ([pscustomobject]@{ id = 'id-unknown'; UserPrincipalName = 'other@contoso.test'; mail = 'accueil@contoso.test' }) | Should -BeTrue
    }

    It 'does not match a real user' {
        Test-PSITNonUserMailbox -Index $script:Index -User ([pscustomobject]@{ id = 'id-user'; UserPrincipalName = 'real.person@contoso.test' }) | Should -BeFalse
    }
}

Describe 'Get-CIPPAlertInactiveUsers shared mailbox exclusion' {
    BeforeEach {
        $script:CapturedData = $null

        Mock -CommandName Write-LogMessage -MockWith { }
        Mock -CommandName Write-AlertTrace -MockWith {
            param($cmdletName, $tenantFilter, $data)
            $script:CapturedData = $data
        }

        # One real user and one shared mailbox, both stale for well over the alert window.
        Mock -CommandName New-GraphGetRequest -MockWith {
            @(
                [pscustomobject]@{
                    id                = 'id-user'
                    UserPrincipalName = 'real.person@contoso.test'
                    userType          = 'Member'
                    signInActivity    = [pscustomobject]@{ lastSignInDateTime = (Get-Date).AddDays(-400).ToString('o') }
                }
                [pscustomobject]@{
                    id                = 'id-shared'
                    UserPrincipalName = 'accueil@contoso.test'
                    userType          = 'Member'
                    signInActivity    = [pscustomobject]@{ lastSignInDateTime = (Get-Date).AddDays(-400).ToString('o') }
                }
            )
        }

        Mock -CommandName Get-CIPPDbItem -MockWith {
            @(
                New-MailboxItem 'id-user' 'real.person@contoso.test' 'UserMailbox'
                New-MailboxItem 'id-shared' 'accueil@contoso.test' 'SharedMailbox'
            )
        }
    }

    It 'reports both accounts when the exclusion is off' {
        Get-CIPPAlertInactiveUsers -TenantFilter 'contoso.onmicrosoft.com' -InputValue @{ DaysSinceLastLogin = 90 }

        @($script:CapturedData).Count | Should -Be 2
    }

    It 'drops the shared mailbox when the exclusion is on' {
        Get-CIPPAlertInactiveUsers -TenantFilter 'contoso.onmicrosoft.com' -InputValue @{ DaysSinceLastLogin = 90; ExcludeSharedMailboxes = $true }

        @($script:CapturedData).Count | Should -Be 1
        @($script:CapturedData)[0].UserPrincipalName | Should -Be 'real.person@contoso.test'
    }

    It 'keeps reporting everything when the exclusion is on but the mailbox cache is empty' {
        Mock -CommandName Get-CIPPDbItem -MockWith { @() }

        Get-CIPPAlertInactiveUsers -TenantFilter 'contoso.onmicrosoft.com' -InputValue @{ DaysSinceLastLogin = 90; ExcludeSharedMailboxes = $true }

        @($script:CapturedData).Count | Should -Be 2
    }

    It 'does not read the mailbox cache at all when the exclusion is off' {
        Get-CIPPAlertInactiveUsers -TenantFilter 'contoso.onmicrosoft.com' -InputValue @{ DaysSinceLastLogin = 90 }

        Should -Invoke Get-CIPPDbItem -Times 0
    }
}
