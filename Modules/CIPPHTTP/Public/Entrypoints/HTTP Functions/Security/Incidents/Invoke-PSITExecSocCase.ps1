Function Invoke-PSITExecSocCase {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Security.Incident.ReadWrite
    .DESCRIPTION
        Creates or updates one SOC triage case: adoption of a Defender/MDO incident, manual
        creation from an external SOC notification, qualification (with justification, analyst
        and timestamp), guide progress, status changes and closure, and the recording of actions
        taken outside CIPP. Every change is appended to the case's action log.

        Writes nothing to the customer tenant: the case lives in CIPP's own storage. The actions
        a case triggers on the tenant (revoke sessions, remove a rule...) go through their own
        endpoints and their own RBAC; this one only keeps the record.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    # Every scalar goes through the unwrapper: the frontend's autoComplete submits {label, value}
    # rather than the value, and a field that misses this fails either loudly (a validated
    # parameter throws) or silently (a loosely parsed one is dropped, and the case is created
    # without it).
    $TenantFilter = Get-PSITSocRequestValue -Value $Request.Body.tenantFilter

    if ([string]::IsNullOrWhiteSpace($TenantFilter)) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'tenantFilter is required.' }
            })
    }

    # A dossier is stored under its tenant, so an unknown one files it where nobody will look for
    # it - and nothing downstream would have complained. A caller once sent the literal string
    # 'tenant', because an unresolved column name falls back to itself, and the endpoint answered
    # 200 with a case id under a client that does not exist. Names that resolve to nothing are
    # refused here rather than written.
    if ($TenantFilter -ne 'AllTenants' -and -not (Get-Tenants -TenantFilter $TenantFilter -IncludeErrors)) {
        Write-LogMessage -headers $Request.Headers -API 'PSITExecSocCase' -tenant $TenantFilter -message "Refused a SOC case for an unknown tenant '$TenantFilter'." -sev Warn
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = "No managed tenant matches '$TenantFilter': the dossier was not created." }
            })
    }

    # The same header-to-name resolution as the BEC triage: a qualification without a name and a
    # timestamp is not an audit trail.
    $Analyst = Get-PSITBecAnalyst -Headers $Request.Headers

    $Parameters = @{
        TenantFilter = $TenantFilter
        Analyst      = $Analyst
    }
    # Scalars pass through when present; Set-PSITSocCase owns the validation so the rules live
    # in one place whatever the caller.
    foreach ($Name in @('CaseId', 'Title', 'Source', 'Severity', 'SeverityTag', 'Status', 'ExternalRef', 'TicketRef', 'TicketUrl', 'Verdict', 'Justification', 'RootCause')) {
        $Value = Get-PSITSocRequestValue -Value $Request.Body.$Name
        if (-not [string]::IsNullOrWhiteSpace($Value)) { $Parameters.$Name = [string]$Value }
    }
    # Taking a case assigns it to the caller, never to a name the caller supplies: an analyst
    # claiming work is not the same gesture as handing it to someone else, and only the second
    # should be able to write another person's name onto a case.
    if ($Request.Body.TakeOwnership -eq $true) {
        # Two analysts clicking 'Prendre en charge' seconds apart used to both win, last write
        # silently erasing the first: the second click now sees who holds the case instead.
        # (A read-then-write window of milliseconds remains; the failure mode being guarded is
        # two humans, seconds apart.)
        $CurrentCaseId = Get-PSITSocRequestValue -Value $Request.Body.CaseId
        if (-not [string]::IsNullOrWhiteSpace($CurrentCaseId)) {
            $Current = @(Get-PSITSocCase -TenantFilter $TenantFilter -CaseId $CurrentCaseId) | Select-Object -First 1
            $Holder = [string]$Current.AssignedTo
            if (-not [string]::IsNullOrWhiteSpace($Holder) -and $Holder -ne $Analyst) {
                return ([HttpResponseContext]@{
                        StatusCode = [HttpStatusCode]::Conflict
                        Body       = @{ Results = "Ce dossier vient d'être pris par $Holder : rafraîchissez la file. Pour le récupérer, passez par « Réattribuer »." }
                    })
            }
        }
        $Parameters.AssignedTo = $Analyst
    } elseif ($null -ne $Request.Body.AssignedTo) {
        # Reassignment, including release: an empty string is a value here, not a missing one.
        $Parameters.AssignedTo = [string](Get-PSITSocRequestValue -Value $Request.Body.AssignedTo)
    }

    $TypeId = Get-PSITSocRequestValue -Value $Request.Body.TypeId
    if ($null -ne $TypeId -and "$TypeId" -match '^\d+$') {
        $Parameters.TypeId = [int]$TypeId
    }
    if ($null -ne $Request.Body.Entities) { $Parameters.Entities = $Request.Body.Entities }
    # An array parameter: an empty array is a value (clearing the techniques), absent is absent.
    if ($null -ne $Request.Body.AttackTechniques) { $Parameters.AttackTechniques = @($Request.Body.AttackTechniques | ForEach-Object { [string](Get-PSITSocRequestValue -Value $_) } | Where-Object { $_ }) }
    if ($null -ne $Request.Body.GuideProgress) { $Parameters.GuideProgress = @($Request.Body.GuideProgress) }
    if ($null -ne $Request.Body.LogAction) { $Parameters.LogAction = $Request.Body.LogAction }

    try {
        $Case = Set-PSITSocCase @Parameters
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @{
                    Results = "SOC case $($Case.CaseId) saved by $Analyst."
                    Case    = $Case
                }
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'PSITExecSocCase' -tenant $TenantFilter -message "Failed to save SOC case $($Request.Body.CaseId): $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = "Could not save the SOC case: $($ErrorMessage.NormalizedError)" }
            })
    }
}
