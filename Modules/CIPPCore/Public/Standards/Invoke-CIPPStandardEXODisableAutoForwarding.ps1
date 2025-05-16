function Invoke-CIPPStandardEXODisableAutoForwarding {
    <#
    .FUNCTIONALITY
        Internal
    .COMPONENT
        (APIName) EXODisableAutoForwarding
    .SYNOPSIS
        (Label) Disable automatic forwarding to external recipients
    .DESCRIPTION
        (Helptext) Disables the ability for users to automatically forward e-mails to external recipients.
        (DocsDescription) Disables the ability for users to automatically forward e-mails to external recipients. This is to prevent data exfiltration. Please check if there are any legitimate use cases for this feature before implementing, like forwarding invoices and such.
    .NOTES
        CAT
            Exchange Standards
        TAG
            "CIS"
            "mdo_autoforwardingmode"
            "mdo_blockmailforward"
        ADDEDCOMPONENT
        IMPACT
            High Impact
        ADDEDDATE
            2024-07-26
        POWERSHELLEQUIVALENT
            Set-HostedOutboundSpamFilterPolicy -AutoForwardingMode 'Off'
        RECOMMENDEDBY
            "CIS"
            "CIPP"
        UPDATECOMMENTBLOCK
            Run the Tools\Update-StandardsComments.ps1 script to update this comment block
    .LINK
        https://docs.cipp.app/user-documentation/tenant/standards/list-standards/exchange-standards#high-impact
    #>

    param($Tenant, $Settings)

    $CurrentInfo = New-ExoRequest -tenantid $Tenant -cmdlet 'Get-HostedOutboundSpamFilterPolicy' -cmdParams @{ Identity = 'Default' } -useSystemMailbox $true
    $StateIsCorrect = $CurrentInfo.AutoForwardingMode -eq 'Off'

    # Récupération des politiques et règles existantes
    $Policies = New-ExoRequest -tenantid $Tenant -cmdlet 'Get-HostedOutboundSpamFilterPolicy' -cmdParams @{} -useSystemMailbox $true
    $Rules    = New-ExoRequest -tenantid $Tenant -cmdlet 'Get-HostedOutboundSpamFilterRule' -cmdParams @{} -useSystemMailbox $true

    $AutoForwardPolicyExists = $Policies | Where-Object { $_.Name -eq 'PleinSudIT - AutoForward Outbound Rule' }
    $AntiSpamPolicyExists    = $Policies | Where-Object { $_.Name -eq 'PleinSudIT - AntiSpam Outbound Rule Standard' }

    $AutoForwardRuleExists = $Rules | Where-Object { $_.Name -eq 'PleinSudIT - AutoForward Outbound Rule' }
    $AntiSpamRuleExists    = $Rules | Where-Object { $_.Name -eq 'PleinSudIT - AntiSpam Outbound Rule Standard' }

    if ($Settings.remediate -eq $true) {

        try {
            New-ExoRequest -tenantid $tenant -cmdlet 'Set-HostedOutboundSpamFilterPolicy' -cmdParams @{ Identity = 'Default'; AutoForwardingMode = 'Off' } -useSystemMailbox $true
            Write-LogMessage -API 'Standards' -tenant $tenant -message 'Disabled auto forwarding' -sev Info
        } catch {
            $ErrorMessage = Get-CippException -Exception $_
            Write-LogMessage -API 'Standards' -tenant $tenant -message "Could not disable auto forwarding. $($ErrorMessage.NormalizedError)" -sev Error
        }

        if (-not $AutoForwardPolicyExists -and -not $AutoForwardRuleExists) {
            try {
                New-ExoRequest -tenantid $tenant -cmdlet 'New-HostedOutboundSpamFilterPolicy' -cmdParams @{
                    Name                         = 'PleinSudIT - AutoForward Outbound Rule'
                    AutoForwardingEnabled        = 'On'
                    RecipientLimitPerHour        = 1000
                    ExternalRecipientLimitPerHour = 500
                    DailyRecipientLimit          = 1000
                    ActionWhenThresholdReached   = 'BlockUser'
                } -useSystemMailbox $true

                New-ExoRequest -tenantid $tenant -cmdlet 'New-HostedOutboundSpamFilterRule' -cmdParams @{
                    Name                         = 'PleinSudIT - AutoForward Outbound Rule'
                    Priority                     = 0
                    Enabled                      = $true
                    SentToMemberOf               = 'gp_autoforward_Allow@defaultdomain.com'
                    HostedOutboundSpamFilterPolicy = 'PleinSudIT - AutoForward Outbound Rule'
                } -useSystemMailbox $true

                Write-LogMessage -API 'Standards' -tenant $tenant -message 'Created AutoForward outbound spam rule' -sev Info
            } catch {
                $ErrorMessage = Get-CippException -Exception $_
                Write-LogMessage -API 'Standards' -tenant $tenant -message "Failed to create AutoForward rule. $($ErrorMessage.NormalizedError)" -sev Error
            }
        } else {
            Write-LogMessage -API 'Standards' -tenant $tenant -message 'AutoForward policy or rule already exists, skipping creation' -sev Info
        }

        if (-not $AntiSpamPolicyExists -and -not $AntiSpamRuleExists) {
            try {
                New-ExoRequest -tenantid $tenant -cmdlet 'New-HostedOutboundSpamFilterPolicy' -cmdParams @{
                    Name                         = 'PleinSudIT - AntiSpam Outbound Rule Standard'
                    AutoForwardingEnabled        = 'Off'
                    RecipientLimitPerHour        = 1000
                    ExternalRecipientLimitPerHour = 500
                    DailyRecipientLimit          = 1000
                    ActionWhenThresholdReached   = 'BlockUser'
                } -useSystemMailbox $true

                New-ExoRequest -tenantid $tenant -cmdlet 'New-HostedOutboundSpamFilterRule' -cmdParams @{
                    Name                         = 'PleinSudIT - AntiSpam Outbound Rule Standard'
                    Priority                     = 1
                    Enabled                      = $true
                    RecipientDomainIs            = 'defaultdomain.com'
                    HostedOutboundSpamFilterPolicy = 'PleinSudIT - AntiSpam Outbound Rule Standard'
                } -useSystemMailbox $true

                Write-LogMessage -API 'Standards' -tenant $tenant -message 'Created AntiSpam standard outbound spam rule' -sev Info
            } catch {
                $ErrorMessage = Get-CippException -Exception $_
                Write-LogMessage -API 'Standards' -tenant $tenant -message "Failed to create AntiSpam standard rule. $($ErrorMessage.NormalizedError)" -sev Error
            }
        } else {
            Write-LogMessage -API 'Standards' -tenant $tenant -message 'AntiSpam policy or rule already exists, skipping creation' -sev Info
        }
    }

    if ($Settings.alert -eq $true) {
        if ($StateIsCorrect -eq $true) {
            Write-LogMessage -API 'Standards' -tenant $tenant -message 'Auto forwarding is disabled.' -sev Info
        } else {
            Write-StandardsAlert -message 'Auto forwarding is not disabled' -object ($CurrentInfo | Select-Object AutoForwardingMode) -tenant $tenant -standardName 'EXODisableAutoForwarding' -standardId $Settings.standardId
            Write-LogMessage -API 'Standards' -tenant $tenant -message 'Auto forwarding is not disabled.' -sev Info
        }
    }

    if ($Settings.report -eq $true) {
        $state = $StateIsCorrect ? $true : $CurrentInfo | Select-Object autoForwardingMode
        Set-CIPPStandardsCompareField -FieldName 'standards.EXODisableAutoForwarding' -FieldValue $state -TenantFilter $Tenant
        Add-CIPPBPAField -FieldName 'AutoForwardingDisabled' -FieldValue $StateIsCorrect -StoreAs bool -Tenant $tenant
    }
}
