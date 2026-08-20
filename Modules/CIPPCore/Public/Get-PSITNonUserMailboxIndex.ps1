function Get-PSITNonUserMailboxIndex {
    <#
    .SYNOPSIS
        Index of the mailboxes whose inactivity is expected rather than actionable.

    .DESCRIPTION
        Shared, room, equipment and scheduling mailboxes exist in Entra as regular member
        users, so Graph /users cannot tell them apart from real people and the inactivity
        alerts report them as stale accounts. Graph exposes no recipient type, but the
        reporting database's cached Mailboxes dataset already carries recipientTypeDetails
        together with ExternalDirectoryObjectId, so the mapping needs no extra Graph or
        Exchange call.

        Returns a case-insensitive HashSet keyed on the Entra object id, the UPN and the
        primary SMTP address, so a caller can test whichever identifier it holds.

        Returns $null when the tenant has no cached mailbox data, which lets callers tell
        'nothing to exclude' (empty set) from 'cache not synced yet' (null) and leave their
        alert unfiltered instead of silently under-reporting.

    .PARAMETER TenantFilter
        The tenant to build the index for.

    .PARAMETER RecipientTypeDetails
        Recipient types to treat as non-user mailboxes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,
        [string[]]$RecipientTypeDetails = @('SharedMailbox', 'RoomMailbox', 'EquipmentMailbox', 'SchedulingMailbox')
    )

    try {
        $MailboxItems = Get-CIPPDbItem -TenantFilter $TenantFilter -Type 'Mailboxes' | Where-Object { $_.RowKey -ne 'Mailboxes-Count' }
    } catch {
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message "Could not read the cached mailboxes to identify shared mailboxes: $($_.Exception.Message)" -sev Warning
        return $null
    }

    if (-not $MailboxItems) {
        Write-LogMessage -API 'Alerts' -tenant $TenantFilter -message 'No cached mailbox data, so shared mailboxes cannot be identified. Sync the report data to enable the exclusion.' -sev Warning
        return $null
    }

    $Index = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Item in $MailboxItems) {
        $Mailbox = $Item.Data | ConvertFrom-Json -ErrorAction SilentlyContinue
        if (-not $Mailbox) { continue }
        if ($RecipientTypeDetails -notcontains $Mailbox.recipientTypeDetails) { continue }
        foreach ($Key in @($Mailbox.ExternalDirectoryObjectId, $Mailbox.UPN, $Mailbox.primarySmtpAddress)) {
            if ($Key) { $null = $Index.Add([string]$Key) }
        }
    }

    # -NoEnumerate keeps the HashSet whole: a bare return unrolls it to a string array, which
    # silently loses the case-insensitive comparer and turns an empty index into $null.
    Write-Output -NoEnumerate $Index
}
