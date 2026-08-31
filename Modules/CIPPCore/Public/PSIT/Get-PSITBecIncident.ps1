function Get-PSITBecIncident {
    <#
    .SYNOPSIS
        Reads the incident record of a mailbox, if one has been opened.

    .DESCRIPTION
        Returns an empty record with Exists = $false rather than nothing, so the front end can
        offer to open an incident without special-casing a null, and the report generator can
        refuse to render before the record exists.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,

        [Parameter(Mandatory = $true)]
        [string]$UserId
    )

    $Table = Get-CippTable -tablename 'PSITBecIncidents'
    $Row = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$TenantFilter' and RowKey eq '$UserId'"

    # Closed cases on the same mailbox. Archived rows are keyed "<UserId>_<Reference>", so a key
    # range picks them up without scanning the table; '~' sorts above every character a reference
    # can contain. A second compromise of the same mailbox is a finding in itself, so this is
    # returned to the panels and to both reports rather than kept for support.
    $PreviousRows = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$TenantFilter' and RowKey ge '$($UserId)_' and RowKey le '$($UserId)_~'"
    $PreviousList = foreach ($Previous in @($PreviousRows | Where-Object { $_.Reference })) {
        [pscustomobject]@{
            Reference      = [string]$Previous.Reference
            AutotaskTicket = [string]$Previous.AutotaskTicket
            DetectedUtc    = [string]$Previous.DetectedUtc
            ContainedUtc   = [string]$Previous.ContainedUtc
            Status         = [string]$Previous.Status
            ClosedUtc      = [string]$Previous.ClosedUtc
            ClosedBy       = [string]$Previous.ClosedBy
            ClosureNote    = [string]$Previous.ClosureNote
            # Frozen at closure, because CippLogs forgets after 90 days and this row must not.
            ContainmentAttestation = if ([string]::IsNullOrWhiteSpace($Previous.ContainmentAttestation)) { $null } else {
                try { $Previous.ContainmentAttestation | ConvertFrom-Json -ErrorAction Stop } catch { $null }
            }
        }
    }
    $PreviousCases = @(@($PreviousList) | Sort-Object -Property ClosedUtc -Descending)

    $AsList = {
        param($Value)
        if ([string]::IsNullOrWhiteSpace($Value)) { return @() }
        try { return @($Value | ConvertFrom-Json -ErrorAction Stop) } catch { return @() }
    }

    return [pscustomobject]@{
        Exists                  = [bool]$Row.Reference
        TenantFilter            = $TenantFilter
        UserId                  = $UserId
        UserPrincipalName       = [string]$Row.UserPrincipalName
        Reference               = [string]$Row.Reference
        AutotaskTicket          = [string]$Row.AutotaskTicket
        DetectedUtc             = [string]$Row.DetectedUtc
        ContainedUtc            = [string]$Row.ContainedUtc
        Status                  = [string]$Row.Status
        DataSubjectCategories   = & $AsList $Row.DataSubjectCategories
        DataCategories          = & $AsList $Row.DataCategories
        AffectedPersonsEstimate = [string]$Row.AffectedPersonsEstimate
        AffectedPersonsBasis    = [string]$Row.AffectedPersonsBasis
        MailReadStatus          = [string]$Row.MailReadStatus
        LikelyConsequences      = [string]$Row.LikelyConsequences
        ExecutiveNote           = [string]$Row.ExecutiveNote
        # No stored value on a record opened before the field existed: the strictest marking is the
        # safe default for a document already in circulation.
        Tlp                     = if ($Row.Tlp) { [string]$Row.Tlp } else { 'TLP:AMBER+STRICT' }
        EffectDescription       = [string]$Row.EffectDescription
        EffectDescriptionOther  = [string]$Row.EffectDescriptionOther
        RelatedTickets          = & $AsList $Row.RelatedTickets
        DeliveredTo             = [string]$Row.DeliveredTo
        DeliveredUtc            = [string]$Row.DeliveredUtc
        DeliveryChannel         = [string]$Row.DeliveryChannel
        AcknowledgedBy          = [string]$Row.AcknowledgedBy
        FollowUpDecision        = [string]$Row.FollowUpDecision
        FollowUpDecisionUtc     = [string]$Row.FollowUpDecisionUtc
        AcknowledgedUtc         = [string]$Row.AcknowledgedUtc
        ExternalActions         = & $AsList $Row.ExternalActions
        ThirdPartiesNotified    = & $AsList $Row.ThirdPartiesNotified
        CreatedBy               = [string]$Row.CreatedBy
        CreatedUtc              = [string]$Row.CreatedUtc
        UpdatedBy               = [string]$Row.UpdatedBy
        UpdatedUtc              = [string]$Row.UpdatedUtc
        PreviousCases           = $PreviousCases
        RepeatOffence           = @($PreviousCases).Count -gt 0
    }
}
