function Set-PSITBecIncident {
    <#
    .SYNOPSIS
        Records the incident-management facts a confirmed BEC report needs and CIPP cannot know.

    .DESCRIPTION
        Roughly 60 percent of an incident report is data CIPP already holds - the timeline, the
        evidence, the remediation trail. The rest exists only in the analyst's head or in the
        client's answers: when it was detected, when it was contained, which categories of personal
        data the mailbox held, how many people that represents, which third parties were warned.

        Those fields are stored here rather than typed into a document, so the report is generated
        from a record instead of being hand-written, and so the same facts can be re-rendered
        months later without anyone remembering them.

        The data-category fields deliberately mirror what GDPR article 33(3) requires a controller
        to describe: the nature of the breach, the categories and approximate number of data
        subjects, the categories and volume of records, the likely consequences, and the measures
        taken. Filling them means the client's DPO has to decide and sign, not investigate.

        This function never states whether a notification is required: that is the controller's
        call, and a processor writing "notifiable" in a report is doing legal work it has no
        mandate for.

    .PARAMETER Reference
        Incident reference. Generated on first save and kept stable afterwards.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,

        [Parameter(Mandatory = $true)]
        [string]$UserId,

        [string]$UserPrincipalName,

        [Parameter(Mandatory = $true)]
        [string]$Analyst,

        [string]$Reference,

        # The MSP's own case reference. Carried on both reports, because "PSIT-BEC-20260820-AFF6"
        # means nothing to a client who tracks the incident by its Autotask ticket.
        [string]$AutotaskTicket,

        [string]$DetectedUtc,
        [string]$ContainedUtc,

        [ValidateSet('ongoing', 'contained', 'monitoring', 'closed')]
        [string]$Status,

        [string[]]$DataSubjectCategories,
        [string[]]$DataCategories,
        [string]$AffectedPersonsEstimate,
        [string]$AffectedPersonsBasis,

        [ValidateSet('proven', 'not-provable', 'excluded', 'unknown')]
        [string]$MailReadStatus,

        [string]$LikelyConsequences,
        [string]$ExecutiveNote,

        # Marking of the report, per FIRST's Traffic Light Protocol. A property of the case, not a
        # constant of the template: the controller may ask for a wider distribution, and the reports
        # must then say so on every page rather than keep a stale AMBER+STRICT.
        [ValidateSet('TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED')]
        [string]$Tlp,

        # What the unauthorised access was followed by. An enumeration and never a deduction: the
        # collection cannot tell a hijacked thread from a mass send, and the summary states it as
        # fact.
        [ValidateSet('mass-send', 'thread-hijack', 'both', 'access-only', 'other')]
        [string]$EffectDescription,

        # Only with EffectDescription = 'other'. Logged on save so the enumeration can be widened
        # from real cases instead of guesses.
        [string]$EffectDescriptionOther,

        # Other tickets covering the same incident. The main ticket stays AutotaskTicket.
        $RelatedTickets,

        # Who the report was handed to, when and how, and who acknowledged it. An incident report
        # is a piece of evidence in a dispute with an insurer or a client: "we told them" has to be
        # recorded at the time, not reconstructed from memory a year later.
        [string]$DeliveredTo,
        [string]$DeliveredUtc,
        [string]$DeliveryChannel,
        [string]$AcknowledgedBy,
        [string]$AcknowledgedUtc,

        # Actions taken outside CIPP: the bank called, a supplier warned, a complaint filed. Kept
        # separate from the CIPP log so the report can say which is attested and which is declared.
        $ExternalActions,

        $ThirdPartiesNotified
    )

    $Table = Get-CippTable -tablename 'PSITBecIncidents'
    $Existing = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$TenantFilter' and RowKey eq '$UserId'"
    $Now = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')

    $ValidateStamp = {
        param($Value, $FieldName)
        if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
        $Parsed = [datetime]::MinValue
        if (-not [datetime]::TryParse($Value, [ref]$Parsed)) {
            throw "$FieldName is not a valid date and time: '$Value'."
        }
        return $Parsed.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }

    # Validated once, because the reference is derived from it: a reference reading PSIT-BEC-20260820
    # on an incident detected in July invites the wrong date to be quoted from it.
    $DetectedStamp = & $ValidateStamp $DetectedUtc 'DetectedUtc'
    $ContainedStamp = & $ValidateStamp $ContainedUtc 'ContainedUtc'

    $IncidentReference = if ($Reference) {
        $Reference
    } elseif ($Existing.Reference) {
        [string]$Existing.Reference
    } else {
        # Stable, sortable, and meaningful to a human reading a ticket queue. Dated on the detection
        # when the first save carries one, on the day the file was opened otherwise - and computed
        # only once, so it never moves afterwards.
        $ReferenceDate = if ($DetectedStamp) { ([datetime]$DetectedStamp).ToString('yyyyMMdd') } else { [datetime]::UtcNow.ToString('yyyyMMdd') }
        'PSIT-BEC-{0}-{1}' -f $ReferenceDate, ([guid]::NewGuid().ToString().Substring(0, 4).ToUpperInvariant())
    }

    # The channel enumeration lives here as well as in the panel: a value typed straight into the
    # endpoint would otherwise reach a client report, which is how "Pigeon voyageur" got printed.
    $ValidChannels = @('courriel', 'telephone', 'portail', 'courrier')
    $ValidateChannel = {
        param($Value, $FieldName)
        if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
        if ($ValidChannels -notcontains [string]$Value) {
            throw "$FieldName must be one of: $($ValidChannels -join ', '). Received '$Value'."
        }
        return [string]$Value
    }

    $Keep = {
        param($New, $OldValue)
        if ($null -ne $New -and -not [string]::IsNullOrWhiteSpace([string]$New)) { return $New }
        return $OldValue
    }
    $KeepList = {
        param($New, $OldJson)
        if ($null -ne $New) { return [string](@($New) | ConvertTo-Json -Depth 6 -Compress -AsArray) }
        if ($OldJson) { return [string]$OldJson }
        return '[]'
    }

    # Same constraint inside the list: one row with a fanciful channel is enough to discredit an
    # annex.
    if ($null -ne $ThirdPartiesNotified) {
        foreach ($Row in @($ThirdPartiesNotified)) {
            if ($Row -and $Row.Channel) { $null = & $ValidateChannel $Row.Channel 'ThirdPartiesNotified.Channel' }
        }
    }

    if ($EffectDescription -eq 'other' -and -not [string]::IsNullOrWhiteSpace($EffectDescriptionOther)) {
        Write-LogMessage -API 'PSITBecIncident' -tenant $TenantFilter -message "Effect description entered as free text on $($IncidentReference): $EffectDescriptionOther" -sev Info
    }

    $Entity = @{
        PartitionKey            = $TenantFilter
        RowKey                  = $UserId
        UserPrincipalName       = & $Keep $UserPrincipalName ([string]$Existing.UserPrincipalName)
        Reference               = $IncidentReference
        AutotaskTicket          = & $Keep $AutotaskTicket ([string]$Existing.AutotaskTicket)
        DetectedUtc             = & $Keep $DetectedStamp ([string]$Existing.DetectedUtc)
        ContainedUtc            = & $Keep $ContainedStamp ([string]$Existing.ContainedUtc)
        Status                  = & $Keep $Status ([string]$Existing.Status)
        DataSubjectCategories   = & $KeepList $DataSubjectCategories $Existing.DataSubjectCategories
        DataCategories          = & $KeepList $DataCategories $Existing.DataCategories
        AffectedPersonsEstimate = & $Keep $AffectedPersonsEstimate ([string]$Existing.AffectedPersonsEstimate)
        AffectedPersonsBasis    = & $Keep $AffectedPersonsBasis ([string]$Existing.AffectedPersonsBasis)
        MailReadStatus          = & $Keep $MailReadStatus ([string]$Existing.MailReadStatus)
        LikelyConsequences      = & $Keep $LikelyConsequences ([string]$Existing.LikelyConsequences)
        ExecutiveNote           = & $Keep $ExecutiveNote ([string]$Existing.ExecutiveNote)
        # Default applied on creation only, so a case marked TLP:GREEN on purpose is not silently
        # pulled back to the stricter default by the next save.
        Tlp                     = & $Keep $Tlp (& $Keep ([string]$Existing.Tlp) 'TLP:AMBER+STRICT')
        EffectDescription       = & $Keep $EffectDescription ([string]$Existing.EffectDescription)
        EffectDescriptionOther  = & $Keep $EffectDescriptionOther ([string]$Existing.EffectDescriptionOther)
        RelatedTickets          = & $KeepList $RelatedTickets $Existing.RelatedTickets
        DeliveredTo             = & $Keep $DeliveredTo ([string]$Existing.DeliveredTo)
        DeliveredUtc            = & $Keep (& $ValidateStamp $DeliveredUtc 'DeliveredUtc') ([string]$Existing.DeliveredUtc)
        DeliveryChannel         = & $Keep (& $ValidateChannel $DeliveryChannel 'DeliveryChannel') ([string]$Existing.DeliveryChannel)
        AcknowledgedBy          = & $Keep $AcknowledgedBy ([string]$Existing.AcknowledgedBy)
        AcknowledgedUtc         = & $Keep (& $ValidateStamp $AcknowledgedUtc 'AcknowledgedUtc') ([string]$Existing.AcknowledgedUtc)
        ExternalActions         = & $KeepList $ExternalActions $Existing.ExternalActions
        ThirdPartiesNotified    = & $KeepList $ThirdPartiesNotified $Existing.ThirdPartiesNotified
        UpdatedBy               = $Analyst
        UpdatedUtc              = $Now
        CreatedUtc              = if ($Existing.CreatedUtc) { [string]$Existing.CreatedUtc } else { $Now }
        CreatedBy               = if ($Existing.CreatedBy) { [string]$Existing.CreatedBy } else { $Analyst }
    }

    $null = Add-CIPPAzDataTableEntity @Table -Entity $Entity -Force
    Write-LogMessage -API 'PSITBecIncident' -tenant $TenantFilter -message "Incident record $IncidentReference updated for $($Entity.UserPrincipalName) by $Analyst" -sev Info

    return Get-PSITBecIncident -TenantFilter $TenantFilter -UserId $UserId
}
