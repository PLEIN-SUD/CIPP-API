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

        # How the case reached us, not what detected the event. The external SOC transports
        # Defender, Defender for Office and Entra detections alike, so the two are separate
        # fields: filing an endpoint detection under the channel it arrived through attributes a
        # false source, and double counts the event when it also arrives from the portal.
        [ValidateSet('extsoc', 'xdr', 'mdo', 'manual')]
        [string]$Source,

        # The product that detected the event, when it is known.
        [ValidateSet('xdr', 'mdo', 'entra', 'gws', 's1', 'unknown')]
        [string]$DetectionSource,

        # Deliberately permissive rather than an exact list: the catalogue of types lives in the
        # frontend, next to the guides, and a new type should not need an API release to land. An
        # id with no catalogue entry renders as unknown, which is visible; refusing it here would
        # only move the problem to a moment when nobody can act on it.
        [ValidateRange(1, 99)]
        [int]$TypeId,

        [ValidateSet('P1', 'P2', 'P3', 'P4')]
        [string]$Severity,

        [ValidateSet('new', 'investigating', 'qualified-fp', 'qualified-tp', 'qualified-btp', 'on-hold', 'contained', 'closed')]
        [string]$Status,

        # Who is on it. Distinct from UpdatedBy, which is whoever last touched the record: a second
        # analyst adding a note would otherwise appear to have taken the case from the first.
        # An empty string releases the case, which is why this one is not skipped when blank.
        [AllowEmptyString()]
        [string]$AssignedTo,

        # Free-form object naming what the case is about: userId, upn, deviceId, deviceName,
        # appId, networkMessageId, ip. The case view decides which context panels to show from
        # the properties present.
        $Entities,

        # What was true before an action changed it. Written by the actions that destroy their own
        # evidence - revoking a consent deletes the grants that justified it - so a report produced
        # afterwards describes the investigation rather than the state the remediation left behind.
        $Evidence,

        [string]$ExternalRef,

        # The MSP's own case reference, free text, same rationale as AutotaskTicket on the BEC
        # incident: nothing reads or writes the ticket itself.
        [string]$TicketRef,

        # Clickable address of the ticket, built by the automation that created it: nothing here
        # reads or writes the ticket itself.
        [string]$TicketUrl,

        # The emitter's own severity wording, kept verbatim next to ours. The taxonomy is explicit
        # that the emitter's text tag is not its SLA priority: the two facts live in two fields,
        # and neither is derived from the other.
        [string]$SeverityTag,

        # The qualification, on the four-outcome taxonomy. 'benign-true-positive' is the MSP's
        # most frequent real case after the true FP: the detection was right, the behaviour is
        # real, and there is no compromise (shadow IT, a knowingly deployed app). Forcing it into
        # 'false-positive' taught the external SOC to stop flagging the pattern, and forcing it
        # into 'true-positive' produced client documents asserting a compromise. 'undetermined'
        # is a real answer too: the question stands, and the case must be able to say so.
        [ValidateSet('false-positive', 'true-positive', 'benign-true-positive', 'undetermined')]
        [string]$Verdict,

        [string]$Justification,

        # MITRE ATT&CK technique ids observed on this case (e.g. 'T1078'). Defaulted per alert
        # type by the frontend catalogue, correctable per case; quoted by the reports.
        [string[]]$AttackTechniques,

        # Why it happened, not what happened: phishing, password reuse, legacy protocol, shadow
        # IT... This is what feeds the recommendations instead of leaving them generic.
        [string]$RootCause,

        # Array of { StepId, State (done|skipped|unknown|pending), Note }: progress on the
        # investigation guide of the case's type, merged per StepId. Each step is a question, so
        # each settled step carries its answer: Note is the analyst's finding ('aucun forward',
        # 'titulaire joint, pas dans le pays'), stamped with By/Utc like the state. 'unknown'
        # means 'looked, cannot answer' - a recorded impasse, distinct from not-done-yet. The
        # note requirement is enforced by the UI (the only writing surface), not here: legacy
        # dossiers and tests keep working without notes.
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
        # Cross-transport dedupe: the same incident arrives as the external SOC's notification AND
        # as a Defender alert, each with its own reference, so the ExternalRef check above never
        # sees them as one. Automated sources only: an analyst creating a dossier by hand has
        # already decided it deserves one.
        if ($Source -in @('extsoc', 'xdr', 'mdo') -and $null -ne $Entities) {
            $Duplicate = Find-PSITSocDuplicateCase -TenantFilter $TenantFilter -TypeId $TypeId -Entities $Entities
            if ($Duplicate) {
                $Reference = if (-not [string]::IsNullOrWhiteSpace($ExternalRef)) { " (réf $ExternalRef)" } else { '' }
                Write-Information "SOC case creation deduplicated on ${TenantFilter}: signal from $Source matches $($Duplicate.CaseId), journaling there instead of creating a twin."
                $Updated = Set-PSITSocCase -TenantFilter $TenantFilter -CaseId $Duplicate.CaseId -Analyst $Analyst -LogAction @{
                    Action = 'duplicate-signal'
                    Detail = "Signal doublon reçu via $Source$Reference : rattaché à ce dossier plutôt qu'ouvert en double."
                }
                # Ephemeral response marker, never persisted: the caller words its answer with it.
                $Updated | Add-Member -NotePropertyName 'Reattached' -NotePropertyValue $true -Force
                return $Updated
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
    $Existing_Qualification_Attack = @($Qualification.AttackTechniques | Where-Object { $_ })
    $Existing_Qualification_RootCause = [string]$Qualification.RootCause

    # The analysis fields can be written before any verdict exists: the Analyse tab is step 5,
    # the verdict is step 7. A bare qualification object carries them until the verdict arrives.
    if (-not $Verdict -and ($PSBoundParameters.ContainsKey('AttackTechniques') -or $PSBoundParameters.ContainsKey('RootCause'))) {
        if (-not $Qualification) { $Qualification = [pscustomobject]@{} }
        $Merged = [ordered]@{}
        foreach ($Property in $Qualification.PSObject.Properties) { $Merged[$Property.Name] = $Property.Value }
        if ($PSBoundParameters.ContainsKey('AttackTechniques')) { $Merged['AttackTechniques'] = @($AttackTechniques) }
        if ($PSBoundParameters.ContainsKey('RootCause')) { $Merged['RootCause'] = [string]$RootCause }
        $Qualification = [pscustomobject]$Merged
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
            # Carried over unless this very call also sets them: the analysis (techniques, root
            # cause) is usually written before the verdict, and a verdict must not erase it.
            AttackTechniques = if ($PSBoundParameters.ContainsKey('AttackTechniques')) { @($AttackTechniques) } else { @($Existing_Qualification_Attack) }
            RootCause        = if ($PSBoundParameters.ContainsKey('RootCause')) { [string]$RootCause } else { [string]$Existing_Qualification_RootCause }
        }
        $SystemLog.Add([pscustomobject]@{ Utc = $Now; Analyst = $Analyst; Action = 'qualified'; Detail = $Verdict })

        # The verdict implies the status unless the caller set one explicitly in the same call.
        # 'undetermined' implies nothing: the case stays where it is, the question stands.
        if (-not $EffectiveStatus) {
            $EffectiveStatus = switch ($Verdict) {
                'false-positive' { 'qualified-fp' }
                'true-positive' { 'qualified-tp' }
                'benign-true-positive' { 'qualified-btp' }
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
    # Closing on 'undetermined' is allowed - sometimes the data will never come - but never
    # silently: unclear is a holding state, and a case that leaves it unresolved must say why.
    if ($NewStatus -eq 'closed' -and $PreviousStatus -ne 'closed') {
        $ClosingVerdict = if ($Verdict) { $Verdict } else { [string]$Qualification.Verdict }
        $HasJustification = -not [string]::IsNullOrWhiteSpace([string]$Justification) -or
            -not [string]::IsNullOrWhiteSpace([string]$Qualification.Justification)
        if ($ClosingVerdict -eq 'undetermined' -and -not $HasJustification) {
            throw "Ce dossier est qualifié indéterminé : sa clôture exige une justification (ce qui a été tenté, ce qui manque)."
        }
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
        if ($State -notin @('done', 'skipped', 'unknown', 'pending')) {
            throw "Invalid guide step state '$State' for step '$StepId'. Expected done, skipped, unknown or pending."
        }
        # The finding travels with the state; a write without one keeps the note already filed
        # (un-ticking a step must not erase what was found when it was ticked).
        $Note = [string]$Step.Note
        if ([string]::IsNullOrWhiteSpace($Note)) { $Note = [string]$Progress[$StepId].Note }
        if ($Note.Length -gt 500) { $Note = $Note.Substring(0, 500) }
        $Progress[$StepId] = [pscustomobject]@{ State = $State; By = $Analyst; Utc = $Now; Note = $Note }
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
        $Entry = [pscustomobject]@{
            Utc     = $Now
            Analyst = $Analyst
            Action  = [string]$LogAction.Action
            Detail  = [string]$LogAction.Detail
        }
        # The analyst may declare when the gesture actually happened: a mail sent at 9:12 and
        # logged at 11:40 are two facts, and the journal keeps both. The recorded time stays
        # server-set and beyond editing; the declared one is refused rather than corrected when
        # unreadable or in the future, because a trail nobody trusts is not a trail.
        if (-not [string]::IsNullOrWhiteSpace([string]$LogAction.OccurredUtc)) {
            try {
                $Occurred = ([datetime]$LogAction.OccurredUtc).ToUniversalTime()
            } catch {
                throw "OccurredUtc '$($LogAction.OccurredUtc)' is not a readable date. Use an ISO form such as 2026-08-27T09:12."
            }
            if ($Occurred -gt [datetime]::UtcNow.AddMinutes(5)) {
                throw 'OccurredUtc is in the future: an action cannot be declared before it happened.'
            }
            $Entry | Add-Member -NotePropertyName OccurredUtc -NotePropertyValue ($Occurred.ToString('yyyy-MM-ddTHH:mm:ssZ'))
        }
        $Log.Add($Entry)
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
    # Merged by key rather than replaced: two remediations on one dossier each keep their own
    # snapshot, and neither erases the other.
    $EvidenceJson = if ($null -ne $Evidence) {
        $Merged = @{}
        if (-not [string]::IsNullOrWhiteSpace($Existing.Evidence)) {
            try {
                ($Existing.Evidence | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $Merged[$_.Name] = $_.Value }
            } catch {
                Write-Information "SOC case ${CaseId}: existing evidence could not be parsed and is being replaced: $($_.Exception.Message)"
            }
        }
        foreach ($Property in ([pscustomobject]$Evidence).PSObject.Properties) { $Merged[$Property.Name] = $Property.Value }
        [string]($Merged | ConvertTo-Json -Depth 8 -Compress)
    } else {
        [string]$Existing.Evidence
    }

    $Entity = @{
        PartitionKey  = $TenantFilter
        RowKey        = $CaseId
        Title         = & $Keep $Title $Existing.Title
        AssignedTo      = if ($PSBoundParameters.ContainsKey('AssignedTo')) { [string]$AssignedTo } else { [string]$Existing.AssignedTo }
        Source          = & $Keep $Source $Existing.Source
        DetectionSource = & $Keep $DetectionSource $Existing.DetectionSource
        TypeId        = if ($PSBoundParameters.ContainsKey('TypeId')) { [string]$TypeId } else { [string]$Existing.TypeId }
        Severity      = & $Keep $Severity $Existing.Severity
        Status        = [string]$NewStatus
        Entities      = $EntitiesJson
        Evidence      = $EvidenceJson
        ExternalRef   = & $Keep $ExternalRef $Existing.ExternalRef
        TicketRef     = & $Keep $TicketRef $Existing.TicketRef
        TicketUrl     = & $Keep $TicketUrl $Existing.TicketUrl
        SeverityTag   = & $Keep $SeverityTag $Existing.SeverityTag
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
