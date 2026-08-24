function Set-PSITSocCase {
    <#
    .SYNOPSIS
        Creates or updates one SOC triage case.

    .DESCRIPTION
        The case is the audit trail of the triage: who qualified what, on what grounds, and what
        was done about it. Three rules make it trustworthy, all inherited from the BEC triage
        (Set-PSITBecTriage):

        - Merge, never replace. Only the fields passed in are touched; two analysts working the
          same case do not overwrite each other's fields.
        - A changed qualification keeps its past. Requalifying a case moves the previous verdict
          into PreviousVerdicts instead of erasing it; a changed mind stays visible. Re-saving
          the same verdict does not pile up identical history rows.
        - Everything writes ActionLog. Each change appends a system entry (who, when, what), and
          an analyst can also record an action taken outside CIPP (an isolation clicked in the
          Defender portal, a client called) so the case tells the whole story, tool or not.

        Adoption is idempotent: creating a case with an ExternalRef that already has a non-closed
        case on the same tenant returns that case rather than a duplicate. Two analysts adopting
        the same Defender incident get the same case.

        Writes nothing to the customer tenant: the case lives in CIPP's own storage.

    .PARAMETER TypeId
        The alert type from the PSIT SOC catalogue (1-18). Type 8 (Google Workspace) is refused:
        out of the CIPP scope by decision of 2026-08-24, alerts of that source are triaged
        outside the tool.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,

        [Parameter(Mandatory = $true)]
        [string]$Analyst,

        # Absent: create. Present: update that case, which must exist.
        [string]$CaseId,

        [string]$Title,

        [ValidateSet('cyna', 'xdr', 'mdo', 'manual')]
        [string]$Source,

        [ValidateRange(1, 18)]
        [int]$TypeId,

        [ValidateSet('P1', 'P2', 'P3', 'P4')]
        [string]$Severity,

        [ValidateSet('new', 'investigating', 'qualified-fp', 'qualified-tp', 'contained', 'closed')]
        [string]$Status,

        # Free-form object naming what the case is about: userId, upn, deviceId, deviceName,
        # appId, networkMessageId, ip. The case view decides which context panels to show from
        # the properties present.
        $Entities,

        [string]$ExternalRef,

        # The MSP's own case reference, free text, same rationale as AutotaskTicket on the BEC
        # incident: nothing reads or writes the ticket itself.
        [string]$TicketRef,

        # The qualification. 'undetermined' is a real answer: the client is unreachable, the
        # question stands, and the case must be able to say so honestly.
        [ValidateSet('false-positive', 'true-positive', 'undetermined')]
        [string]$Verdict,

        [string]$Justification,

        # Array of { StepId, State (done|skipped|pending) }: progress on the investigation guide
        # of the case's type. Merged per StepId.
        $GuideProgress,

        # One analyst-declared log entry: { Action, Detail }. For actions taken outside CIPP.
        $LogAction
    )

    if ($PSBoundParameters.ContainsKey('TypeId') -and $TypeId -eq 8) {
        throw 'Type 8 (Google Workspace) is out of the CIPP scope: these alerts are triaged outside the tool.'
    }
    if (-not [string]::IsNullOrWhiteSpace($Justification) -and -not $Verdict) {
        throw 'A justification only makes sense with a verdict: pass Verdict as well.'
    }

    $Table = Get-CippTable -tablename 'PSITSocCases'
    $Now = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $SystemLog = [System.Collections.Generic.List[object]]::new()

    $Existing = $null
    if (-not [string]::IsNullOrWhiteSpace($CaseId)) {
        $Existing = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$TenantFilter' and RowKey eq '$CaseId'"
        if (-not $Existing) {
            throw "SOC case '$CaseId' does not exist on tenant '$TenantFilter'."
        }
    } else {
        # Create. Required fields first, then the idempotent-adoption check.
        foreach ($Required in @('Source', 'TypeId', 'Title')) {
            if (-not $PSBoundParameters.ContainsKey($Required) -or [string]::IsNullOrWhiteSpace("$($PSBoundParameters[$Required])")) {
                throw "Creating a SOC case requires $Required."
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($ExternalRef)) {
            $Open = @(Get-PSITSocCase -TenantFilter $TenantFilter -ExternalRef $ExternalRef) | Where-Object { $_.Status -ne 'closed' } | Select-Object -First 1
            if ($Open) {
                Write-Information "SOC case for external reference '$ExternalRef' already open on ${TenantFilter}: returning $($Open.CaseId) instead of creating a duplicate."
                return $Open
            }
        }
        # Same shape as the BEC incident reference: date-stamped, human-quotable over the phone.
        $CaseId = 'PSIT-SOC-{0}-{1}' -f [datetime]::UtcNow.ToString('yyyyMMdd'), ([guid]::NewGuid().ToString().Substring(0, 4).ToUpperInvariant())
        $SystemLog.Add([pscustomobject]@{ Utc = $Now; Analyst = $Analyst; Action = 'created'; Detail = "type $TypeId, source $Source" })
    }

    # Keep: overwrite only when a value was actually passed. The counterpart of "merge, never
    # replace" for scalar fields, copied from Set-PSITBecIncident.
    $Keep = {
        param($New, $Old)
        if ($null -ne $New -and -not [string]::IsNullOrWhiteSpace("$New")) { return "$New" }
        return [string]$Old
    }

    # $Status carries a ValidateSet, and assigning a parameter variable re-runs its validation:
    # deriving "no status change" as $null must therefore land in a plain variable.
    $EffectiveStatus = $Status

    # --- qualification, with its history --------------------------------------------------------
    $Qualification = $null
    if ($Existing.Qualification) {
        try {
            $Qualification = $Existing.Qualification | ConvertFrom-Json -ErrorAction Stop
        } catch {
            Write-Information "SOC case ${CaseId}: existing qualification could not be parsed and is being replaced: $($_.Exception.Message)"
        }
    }
    if ($Verdict) {
        $History = [System.Collections.Generic.List[object]]::new()
        if ($Qualification) {
            foreach ($Old in @($Qualification.PreviousVerdicts)) { if ($Old) { $History.Add($Old) } }
            if ([string]$Qualification.Verdict -ne $Verdict -or [string]$Qualification.Justification -ne [string]$Justification) {
                $History.Add([pscustomobject]@{
                        Verdict       = $Qualification.Verdict
                        Justification = $Qualification.Justification
                        Analyst       = $Qualification.Analyst
                        DecidedUtc    = $Qualification.DecidedUtc
                    })
            }
        }
        $Qualification = [pscustomobject]@{
            Verdict          = $Verdict
            Justification    = [string]$Justification
            Analyst          = $Analyst
            DecidedUtc       = $Now
            PreviousVerdicts = @($History)
        }
        $SystemLog.Add([pscustomobject]@{ Utc = $Now; Analyst = $Analyst; Action = 'qualified'; Detail = $Verdict })

        # The verdict implies the status unless the caller set one explicitly in the same call.
        # 'undetermined' implies nothing: the case stays where it is, the question stands.
        if (-not $EffectiveStatus) {
            $EffectiveStatus = switch ($Verdict) {
                'false-positive' { 'qualified-fp' }
                'true-positive' { 'qualified-tp' }
                default { $null }
            }
        }
    }

    # --- status, and the closure stamps that come with it ---------------------------------------
    $PreviousStatus = [string]$Existing.Status
    $NewStatus = if ($EffectiveStatus) { $EffectiveStatus } elseif ($Existing) { $PreviousStatus } else { 'new' }
    if ($EffectiveStatus -and $EffectiveStatus -ne $PreviousStatus) {
        $SystemLog.Add([pscustomobject]@{ Utc = $Now; Analyst = $Analyst; Action = 'status'; Detail = $NewStatus })
    }
    $ClosedUtc = [string]$Existing.ClosedUtc
    $ClosedBy = [string]$Existing.ClosedBy
    if ($NewStatus -eq 'closed' -and $PreviousStatus -ne 'closed') {
        $ClosedUtc = $Now
        $ClosedBy = $Analyst
    } elseif ($NewStatus -ne 'closed' -and $PreviousStatus -eq 'closed') {
        # Reopened: the closure stamps described a closure that no longer stands.
        $ClosedUtc = ''
        $ClosedBy = ''
        $SystemLog.Add([pscustomobject]@{ Utc = $Now; Analyst = $Analyst; Action = 'reopened'; Detail = '' })
    }

    # --- guide progress, merged per step ---------------------------------------------------------
    $Progress = @{}
    if ($Existing.GuideProgress) {
        try {
            $Parsed = $Existing.GuideProgress | ConvertFrom-Json -ErrorAction Stop
            foreach ($Property in $Parsed.PSObject.Properties) { $Progress[$Property.Name] = $Property.Value }
        } catch {
            Write-Information "SOC case ${CaseId}: existing guide progress could not be parsed and is being replaced: $($_.Exception.Message)"
        }
    }
    foreach ($Step in @($GuideProgress)) {
        $StepId = [string]$Step.StepId
        if ([string]::IsNullOrWhiteSpace($StepId)) { continue }
        $State = [string]$Step.State
        if ($State -notin @('done', 'skipped', 'pending')) {
            throw "Invalid guide step state '$State' for step '$StepId'. Expected done, skipped or pending."
        }
        $Progress[$StepId] = [pscustomobject]@{ State = $State; By = $Analyst; Utc = $Now }
    }

    # --- action log ------------------------------------------------------------------------------
    $Log = [System.Collections.Generic.List[object]]::new()
    if ($Existing.ActionLog) {
        try {
            foreach ($Entry in @($Existing.ActionLog | ConvertFrom-Json -ErrorAction Stop)) { if ($Entry) { $Log.Add($Entry) } }
        } catch {
            Write-Information "SOC case ${CaseId}: existing action log could not be parsed and is being replaced: $($_.Exception.Message)"
        }
    }
    if ($LogAction -and -not [string]::IsNullOrWhiteSpace([string]$LogAction.Action)) {
        $Log.Add([pscustomobject]@{
                Utc     = $Now
                Analyst = $Analyst
                Action  = [string]$LogAction.Action
                Detail  = [string]$LogAction.Detail
            })
    }
    foreach ($Entry in $SystemLog) { $Log.Add($Entry) }
    # A table property caps at 64KB: keep the most recent entries rather than fail the write. The
    # cut is announced in the log itself so the trail says it is partial instead of lying by
    # omission.
    if ($Log.Count -gt 200) {
        $Dropped = $Log.Count - 199
        $Log = [System.Collections.Generic.List[object]]@($Log | Select-Object -Last 199)
        $Log.Insert(0, [pscustomobject]@{ Utc = $Now; Analyst = 'system'; Action = 'log-truncated'; Detail = "$Dropped older entries dropped" })
    }

    # --- entities: replace-if-passed. A partial entity merge would let a stale deviceId survive
    # a correction, and the caller sending Entities is the case view, which always sends the
    # complete object. ------------------------------------------------------------------------
    $EntitiesJson = if ($null -ne $Entities) {
        [string]($Entities | ConvertTo-Json -Depth 6 -Compress)
    } else {
        [string]$Existing.Entities
    }

    $Entity = @{
        PartitionKey  = $TenantFilter
        RowKey        = $CaseId
        Title         = & $Keep $Title $Existing.Title
        Source        = & $Keep $Source $Existing.Source
        TypeId        = if ($PSBoundParameters.ContainsKey('TypeId')) { [string]$TypeId } else { [string]$Existing.TypeId }
        Severity      = & $Keep $Severity $Existing.Severity
        Status        = [string]$NewStatus
        Entities      = $EntitiesJson
        ExternalRef   = & $Keep $ExternalRef $Existing.ExternalRef
        TicketRef     = & $Keep $TicketRef $Existing.TicketRef
        Qualification = if ($Qualification) { [string]($Qualification | ConvertTo-Json -Depth 8 -Compress) } else { [string]$Existing.Qualification }
        GuideProgress = [string]([pscustomobject]$Progress | ConvertTo-Json -Depth 6 -Compress)
        ActionLog     = [string](@($Log) | ConvertTo-Json -Depth 6 -Compress -AsArray)
        CreatedUtc    = if ($Existing) { [string]$Existing.CreatedUtc } else { $Now }
        CreatedBy     = if ($Existing) { [string]$Existing.CreatedBy } else { $Analyst }
        UpdatedUtc    = $Now
        UpdatedBy     = $Analyst
        ClosedUtc     = $ClosedUtc
        ClosedBy      = $ClosedBy
    }
    $null = Add-CIPPAzDataTableEntity @Table -Entity $Entity -Force

    Write-LogMessage -API 'PSITSocCase' -tenant $TenantFilter -message "SOC case $CaseId $(if ($Existing) { 'updated' } else { 'created' }) by $Analyst" -sev Info

    return ConvertFrom-PSITSocCaseRow -Row ([pscustomobject]$Entity)
}
