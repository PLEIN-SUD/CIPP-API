function Get-CIPPAlertSnoozeDuration {
    <#
    .SYNOPSIS
        Canonical list of the snooze durations an alert item can be snoozed for.
    .DESCRIPTION
        Single source of truth for the durations accepted by ExecSnoozeAlert, rendered as
        buttons in alert emails and published to webhook consumers. The three call sites had
        drifted apart (the webhook payload still advertised a 'forever' option the API
        rejects), so they all read the list from here instead of repeating it.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param()

    return @(
        [PSCustomObject]@{ Days = 7; Label = '7 Days' }
        [PSCustomObject]@{ Days = 14; Label = '14 Days' }
        [PSCustomObject]@{ Days = 30; Label = '30 Days' }
        [PSCustomObject]@{ Days = 90; Label = '90 Days' }
        [PSCustomObject]@{ Days = 180; Label = '180 Days' }
        [PSCustomObject]@{ Days = 365; Label = '1 Year' }
    )
}
