function Invoke-PSITMailRemediation {
    <#
    .SYNOPSIS
        Soft-deletes a delivered malicious message from the mailboxes that received it.

    .DESCRIPTION
        What an incomplete ZAP leaves to do (SOC triage type 18): the message was judged
        malicious after delivery and is still sitting in inboxes. This moves it to Deleted Items
        (soft delete) for the recipients named, through the Defender analyzedEmails remediation
        API.

        Soft delete rather than hard delete, deliberately: a purge an analyst got wrong is
        recoverable by the user, and the evidence stays available for the investigation. A hard
        delete is a decision for Threat Explorer, with someone who accepts the consequence.

        Two constraints inherited from the API, both learned from upstream's own use of
        analyzedEmails in Invoke-ListMailQuarantineMessageDetails:
        - a start and end time are mandatory, so the message is looked up in a window around its
          reception (or the last 15 days when the case does not carry the time);
        - the tenant needs Defender for Office 365 Plan 2, and the app needs
          SecurityAnalyzedMessage.ReadWrite.All. Both failures are surfaced as themselves rather
          than as an empty result, because "nothing to purge" and "we were not allowed to look"
          must never read the same on an incident.

        Returns what was submitted, not what was deleted: the API queues the remediation, and the
        analyst confirms in the portal. The case log records the request, which is the honest
        claim.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,

        [Parameter(Mandatory = $true)]
        [string]$NetworkMessageId,

        # Recipients to purge for. Empty means every recipient the lookup returns.
        [string[]]$Recipients,

        # Reception time of the message, to bound the lookup window.
        [string]$ReceivedUtc,

        [Parameter(Mandatory = $true)]
        [string]$Analyst
    )

    $MessageGuid = [guid]::Empty
    if (-not [guid]::TryParse($NetworkMessageId, [ref]$MessageGuid)) {
        throw "NetworkMessageId must be a valid GUID: '$NetworkMessageId'."
    }

    $Now = (Get-Date).ToUniversalTime()
    $Received = $null
    if (-not [string]::IsNullOrWhiteSpace($ReceivedUtc)) {
        try { $Received = ([datetime]$ReceivedUtc).ToUniversalTime() } catch { $Received = $null }
    }
    if ($Received) {
        $StartDate = $Received.AddDays(-1)
        $EndDate = $Received.AddDays(1)
    } else {
        $StartDate = $Now.AddDays(-15)
        $EndDate = $Now
    }
    if ($EndDate -gt $Now) { $EndDate = $Now }
    $StartTime = $StartDate.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $EndTime = $EndDate.ToString('yyyy-MM-ddTHH:mm:ssZ')

    $Filter = [System.Uri]::EscapeDataString("networkMessageId eq '$($MessageGuid.Guid)'")
    $Analyzed = @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/security/collaboration/analyzedEmails?startTime=$StartTime&endTime=$EndTime&`$filter=$Filter" -tenantid $TenantFilter -AsApp $true)

    if ($Analyzed.Count -eq 0) {
        throw "No analyzed email found for $($MessageGuid.Guid) between $StartTime and $EndTime. The message may be outside the window, or Defender for Office 365 Plan 2 may not cover this tenant."
    }

    # One analyzed email per recipient: the purge targets the copies, so the recipient filter
    # applies here rather than in the API call.
    $Targets = if ($Recipients -and @($Recipients).Count -gt 0) {
        $Wanted = @($Recipients | ForEach-Object { $_.ToLowerInvariant() })
        @($Analyzed | Where-Object { $Wanted -contains [string]$_.recipientEmailAddress.ToLowerInvariant() })
    } else {
        $Analyzed
    }
    if ($Targets.Count -eq 0) {
        throw 'None of the recipients requested received this message according to Defender.'
    }

    $Body = @{
        displayName             = "SOC triage purge by $Analyst"
        description             = "Soft delete requested from the CIPP SOC dashboard for message $($MessageGuid.Guid)"
        remediationAction       = 'softDelete'
        analyzedEmailIdentifiers = @(
            foreach ($Email in $Targets) {
                @{
                    networkMessageId      = [string]$Email.networkMessageId
                    recipientEmailAddress = [string]$Email.recipientEmailAddress
                }
            }
        )
    } | ConvertTo-Json -Depth 6 -Compress

    $null = New-GraphPOSTRequest -uri 'https://graph.microsoft.com/beta/security/collaboration/analyzedEmails/remediate' -tenantid $TenantFilter -body $Body -AsApp $true

    Write-LogMessage -API 'PSITExecMailRemediate' -tenant $TenantFilter -message "Soft delete requested for message $($MessageGuid.Guid) on $($Targets.Count) recipient(s) by $Analyst" -sev Info

    return [pscustomobject]@{
        NetworkMessageId = $MessageGuid.Guid
        Action           = 'softDelete'
        Recipients       = @($Targets | ForEach-Object { [string]$_.recipientEmailAddress })
        Submitted        = $true
        Results          = @([pscustomobject]@{
                resultText = "Soft delete submitted for $($Targets.Count) copy/copies of the message. Confirm completion in the Defender portal."
                state      = 'success'
            })
    }
}
