function Get-PSITMailEvidence {
    <#
    .SYNOPSIS
        What Defender knows about one delivered message, per recipient.

    .DESCRIPTION
        Reads the Defender analyzedEmails record for a network message id and turns it into the
        facts an analyst needs before deciding anything: who sent it, what it was called, who
        actually received it, where each copy sits now, and what Defender thought of it.

        The purge reads the same record through this function. Two copies of the lookup would
        drift, and the drift would show up at the worst moment: a panel saying the message was
        delivered to four people, and a purge answering that it found nothing.

        The time window is the reason both must agree. analyzedEmails requires a start and an end,
        and the answer changes with them. A message reported with its reception time gets a day on
        either side; without one, the last fifteen days. Widening it further is not free, and
        narrowing it loses messages whose reported time is approximate.

        One record per recipient is what the API returns, and that shape is kept rather than
        flattened: a message delivered to the inbox for one person and quarantined for another is
        two different situations, and an analyst deciding on a purge needs to see both.

    .PARAMETER Analyzed
        Injected records. Fetched when omitted, which is what makes this testable without Graph.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,

        [Parameter(Mandatory = $true)]
        [string]$NetworkMessageId,

        [AllowNull()]
        [string]$ReceivedUtc,

        [AllowNull()]
        $Analyzed
    )

    $MessageGuid = [guid]::Empty
    if (-not [guid]::TryParse($NetworkMessageId, [ref]$MessageGuid)) {
        throw "'$NetworkMessageId' is not a network message id: Defender identifies a message by a GUID."
    }

    $Now = [datetime]::UtcNow
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

    if ($null -eq $Analyzed) {
        $Filter = [System.Uri]::EscapeDataString("networkMessageId eq '$($MessageGuid.Guid)'")
        $Analyzed = @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/security/collaboration/analyzedEmails?startTime=$StartTime&endTime=$EndTime&`$filter=$Filter" -tenantid $TenantFilter -AsApp $true)
    }
    $Analyzed = @($Analyzed)

    $Recipients = foreach ($Email in $Analyzed) {
        [PSCustomObject]@{
            Recipient        = [string]$Email.recipientEmailAddress
            OriginalAction   = [string]$Email.originalDelivery.action
            OriginalLocation = [string]$Email.originalDelivery.location
            LatestAction     = [string]$Email.latestDelivery.action
            LatestLocation   = [string]$Email.latestDelivery.location
            # The one an analyst acts on: a copy still in a mailbox is a copy still readable.
            StillDelivered   = [string]$Email.latestDelivery.location -in @('Inbox', 'JunkFolder', 'Others')
        }
    }
    $Recipients = @($Recipients)

    $First = @($Analyzed)[0]

    return [PSCustomObject]@{
        Message    = if ($null -eq $First) { $null } else {
            [PSCustomObject]@{
                NetworkMessageId  = [string]$First.networkMessageId
                InternetMessageId = [string]$First.internetMessageId
                Subject           = [string]$First.subject
                SenderDisplayName = [string]$First.senderDetail.displayName
                SenderFrom        = [string]$First.senderDetail.fromAddress
                SenderMailFrom    = [string]$First.senderDetail.mailFromAddress
                SenderIp          = [string]$First.senderDetail.ipv4
                SenderLocation    = [string]$First.senderDetail.location
                Directionality    = [string]$First.directionality
                ThreatTypes       = @($First.threatTypes)
                DetectionMethods  = @($First.detectionMethods)
                PolicyAction      = [string]$First.policyAction
                Spf               = [string]$First.authenticationDetails.senderPolicyFramework
                Dkim              = [string]$First.authenticationDetails.dkim
                Dmarc             = [string]$First.authenticationDetails.dmarc
                Urls              = @($First.urls | ForEach-Object { [string]$_.url } | Where-Object { $_ })
                AttachmentCount   = @($First.attachments).Count
            }
        }
        Recipients = $Recipients
        Metadata   = [PSCustomObject]@{
            Found            = $Analyzed.Count -gt 0
            RecipientCount   = $Recipients.Count
            StillDelivered   = @($Recipients | Where-Object { $_.StillDelivered }).Count
            WindowStart      = $StartTime
            WindowEnd        = $EndTime
            # Stated because an empty answer has two causes and they call for different actions:
            # nothing matched inside the window, or the tenant is not covered by the licence the
            # analyzedEmails API needs.
            WindowFromReport = [bool]$Received
        }
    }
}
