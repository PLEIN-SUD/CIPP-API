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

    $TenantFilter = $Request.Body.tenantFilter

    if ([string]::IsNullOrWhiteSpace($TenantFilter)) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'tenantFilter is required.' }
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
    foreach ($Name in @('CaseId', 'Title', 'Source', 'Severity', 'Status', 'ExternalRef', 'TicketRef', 'Verdict', 'Justification')) {
        $Value = $Request.Body.$Name
        if (-not [string]::IsNullOrWhiteSpace($Value)) { $Parameters.$Name = [string]$Value }
    }
    if ($null -ne $Request.Body.TypeId -and "$($Request.Body.TypeId)" -match '^\d+$') {
        $Parameters.TypeId = [int]$Request.Body.TypeId
    }
    if ($null -ne $Request.Body.Entities) { $Parameters.Entities = $Request.Body.Entities }
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
