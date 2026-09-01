function Get-PSITSocCase {
    <#
    .SYNOPSIS
        Reads SOC triage cases: one by id, or a filtered list.

    .DESCRIPTION
        A case is the unit of work of the SOC dashboard: one alert adopted from Defender/MDO or
        typed in from an external SOC notification, carrying its qualification, its guide
        progress and its action log. This reads them back for the queue and the case view.

        Stored JSON fields are parsed defensively: a case whose ActionLog cannot be parsed is
        still a case, and the queue must render it rather than blow up on the whole list. Returns
        an empty array rather than nothing when no case matches, so callers can render "no open
        case" without special-casing a null.

        Every returned object carries its tenant on a 'Tenant' property, which is what
        Select-CippAllowedTenantData filters on when a tenant-restricted role lists AllTenants.
    #>
    [CmdletBinding()]
    param(
        # Default domain name of the tenant, or empty/AllTenants for every tenant.
        [string]$TenantFilter,

        [string]$CaseId,

        [ValidateSet('new', 'investigating', 'qualified-fp', 'qualified-tp', 'qualified-btp', 'on-hold', 'contained', 'closed')]
        [string]$Status,

        [ValidateSet('extsoc', 'xdr', 'mdo', 'manual')]
        [string]$Source,

        # External alert or incident reference (the external SOC's alert number, a Defender incident
        # id). Used by the
        # adoption flow to find an already-created case before creating a duplicate.
        [string]$ExternalRef
    )

    $Table = Get-CippTable -tablename 'PSITSocCases'

    $FilterParts = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($TenantFilter) -and $TenantFilter -ne 'AllTenants') {
        $FilterParts.Add("PartitionKey eq '$TenantFilter'")
    }
    if (-not [string]::IsNullOrWhiteSpace($CaseId)) {
        $FilterParts.Add("RowKey eq '$CaseId'")
    }

    $Rows = if ($FilterParts.Count -gt 0) {
        Get-CIPPAzDataTableEntity @Table -Filter ($FilterParts -join ' and ')
    } else {
        Get-CIPPAzDataTableEntity @Table
    }

    # Status, Source and ExternalRef are filtered in memory: the table is small (cases, not
    # events), and a memory filter cannot be broken by a quote in an externally-supplied
    # reference.
    $Cases = foreach ($Row in @($Rows)) {
        if (-not $Row) { continue }
        if ($Status -and [string]$Row.Status -ne $Status) { continue }
        if ($Source -and [string]$Row.Source -ne $Source) { continue }
        if ($ExternalRef -and [string]$Row.ExternalRef -ne $ExternalRef) { continue }
        ConvertFrom-PSITSocCaseRow -Row $Row
    }

    return @($Cases | Sort-Object -Property UpdatedUtc -Descending)
}

function ConvertFrom-PSITSocCaseRow {
    <#
    .SYNOPSIS
        Turns a PSITSocCases table row into the case object the API returns.

    .DESCRIPTION
        One place for the JSON parsing and the property names, shared by Get-PSITSocCase and
        Set-PSITSocCase, so the object a write returns is byte-for-byte the object the next read
        returns.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Row
    )

    $ParseJson = {
        param($Value, $Fallback)
        if ([string]::IsNullOrWhiteSpace($Value)) { return $Fallback }
        try {
            return ($Value | ConvertFrom-Json -ErrorAction Stop)
        } catch {
            Write-Information "SOC case $($Row.RowKey): a stored JSON field could not be parsed: $($_.Exception.Message)"
            return $Fallback
        }
    }

    return [pscustomobject]@{
        CaseId        = [string]$Row.RowKey
        Tenant        = [string]$Row.PartitionKey
        Source        = [string]$Row.Source
        TypeId        = if ($null -ne $Row.TypeId -and "$($Row.TypeId)" -match '^\d+$') { [int]$Row.TypeId } else { $null }
        Severity      = [string]$Row.Severity
        Status        = [string]$Row.Status
        AssignedTo    = [string]$Row.AssignedTo
        Title         = [string]$Row.Title
        Entities      = & $ParseJson $Row.Entities ([pscustomobject]@{})
        Evidence      = & $ParseJson $Row.Evidence ([pscustomobject]@{})
        ExternalRef   = [string]$Row.ExternalRef
        TicketRef     = [string]$Row.TicketRef
        TicketUrl     = [string]$Row.TicketUrl
        SeverityTag   = [string]$Row.SeverityTag
        Qualification = & $ParseJson $Row.Qualification $null
        GuideProgress = & $ParseJson $Row.GuideProgress ([pscustomobject]@{})
        ActionLog     = @(& $ParseJson $Row.ActionLog @())
        SourceSubject = [string]$Row.SourceSubject
        SourceMail    = [string]$Row.SourceMail
        CreatedUtc    = [string]$Row.CreatedUtc
        CreatedBy     = [string]$Row.CreatedBy
        UpdatedUtc    = [string]$Row.UpdatedUtc
        UpdatedBy     = [string]$Row.UpdatedBy
        ClosedUtc     = [string]$Row.ClosedUtc
        ClosedBy      = [string]$Row.ClosedBy
    }
}
