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

    $IncidentReference = if ($Reference) {
        $Reference
    } elseif ($Existing.Reference) {
        [string]$Existing.Reference
    } else {
        # Stable, sortable, and meaningful to a human reading a ticket queue.
        'PSIT-BEC-{0}-{1}' -f ([datetime]::UtcNow.ToString('yyyyMMdd')), ([guid]::NewGuid().ToString().Substring(0, 4).ToUpperInvariant())
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

    $Entity = @{
        PartitionKey            = $TenantFilter
        RowKey                  = $UserId
        UserPrincipalName       = & $Keep $UserPrincipalName ([string]$Existing.UserPrincipalName)
        Reference               = $IncidentReference
        DetectedUtc             = & $Keep (& $ValidateStamp $DetectedUtc 'DetectedUtc') ([string]$Existing.DetectedUtc)
        ContainedUtc            = & $Keep (& $ValidateStamp $ContainedUtc 'ContainedUtc') ([string]$Existing.ContainedUtc)
        Status                  = & $Keep $Status ([string]$Existing.Status)
        DataSubjectCategories   = & $KeepList $DataSubjectCategories $Existing.DataSubjectCategories
        DataCategories          = & $KeepList $DataCategories $Existing.DataCategories
        AffectedPersonsEstimate = & $Keep $AffectedPersonsEstimate ([string]$Existing.AffectedPersonsEstimate)
        AffectedPersonsBasis    = & $Keep $AffectedPersonsBasis ([string]$Existing.AffectedPersonsBasis)
        MailReadStatus          = & $Keep $MailReadStatus ([string]$Existing.MailReadStatus)
        LikelyConsequences      = & $Keep $LikelyConsequences ([string]$Existing.LikelyConsequences)
        ExecutiveNote           = & $Keep $ExecutiveNote ([string]$Existing.ExecutiveNote)
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
