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
        ExternalActions         = & $AsList $Row.ExternalActions
        ThirdPartiesNotified    = & $AsList $Row.ThirdPartiesNotified
        CreatedBy               = [string]$Row.CreatedBy
        CreatedUtc              = [string]$Row.CreatedUtc
        UpdatedBy               = [string]$Row.UpdatedBy
        UpdatedUtc              = [string]$Row.UpdatedUtc
    }
}
