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

    # The same read the evidence panel uses. Two copies of this lookup would drift, and the drift
    # would surface as a panel saying the message reached four people and a purge finding nothing.
    $Evidence = Get-PSITMailEvidence -TenantFilter $TenantFilter -NetworkMessageId $NetworkMessageId -ReceivedUtc $ReceivedUtc

    if (-not $Evidence.Metadata.Found) {
        throw "No analyzed email found for $NetworkMessageId between $($Evidence.Metadata.WindowStart) and $($Evidence.Metadata.WindowEnd). The message may be outside the window, or Defender for Office 365 Plan 2 may not cover this tenant."
    }

    # After the check, never before: on an empty answer there is no message to read the id from,
    # and the cast would throw over the sentence explaining what happened.
    $MessageGuid = [guid]$Evidence.Message.NetworkMessageId

    # One analyzed email per recipient: the purge targets the copies, so the recipient filter
    # applies here rather than in the API call.
    $Targets = if ($Recipients -and @($Recipients).Count -gt 0) {
        $Wanted = @($Recipients | ForEach-Object { $_.ToLowerInvariant() })
        @($Evidence.Recipients | Where-Object { $Wanted -contains [string]$_.Recipient.ToLowerInvariant() })
    } else {
        @($Evidence.Recipients)
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
                    networkMessageId      = [string]$MessageGuid.Guid
                    recipientEmailAddress = [string]$Email.Recipient
                }
            }
        )
    } | ConvertTo-Json -Depth 6 -Compress

    $null = New-GraphPOSTRequest -uri 'https://graph.microsoft.com/beta/security/collaboration/analyzedEmails/remediate' -tenantid $TenantFilter -body $Body -AsApp $true

    Write-LogMessage -API 'PSITExecMailRemediate' -tenant $TenantFilter -message "Soft delete requested for message $($MessageGuid.Guid) on $($Targets.Count) recipient(s) by $Analyst" -sev Info

    return [pscustomobject]@{
        NetworkMessageId = $MessageGuid.Guid
        Action           = 'softDelete'
        Recipients       = @($Targets | ForEach-Object { [string]$_.Recipient })
        Submitted        = $true
        # Read above, before the purge, and returned so the caller can file it: once the message
        # is soft-deleted the same read answers about the state this action created, and a report
        # written afterwards would say the phishing reached nobody.
        EvidenceBefore   = [pscustomobject]@{
            subject        = [string]$Evidence.Message.Subject
            sender         = [string]$Evidence.Message.Sender
            receivedUtc    = [string]$Evidence.Message.ReceivedUtc
            recipients     = @($Evidence.Recipients | ForEach-Object {
                    [pscustomobject]@{
                        recipient      = [string]$_.Recipient
                        deliveryAction = [string]$_.DeliveryAction
                        stillDelivered = [bool]$_.StillDelivered
                    }
                })
            recipientCount = [int]$Evidence.Metadata.RecipientCount
            stillDelivered = [int]$Evidence.Metadata.StillDelivered
            purgedUtc      = (Get-Date).ToUniversalTime().ToString('o')
        }
        Results          = @([pscustomobject]@{
                resultText = "Soft delete submitted for $($Targets.Count) copy/copies of the message. Confirm completion in the Defender portal."
                state      = 'success'
            })
    }
}
