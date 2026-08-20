Function Invoke-PSITListBecTriage {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Identity.User.Read
    .DESCRIPTION
        Returns the analyst determinations recorded on a user's BEC signals: for each qualified
        signal, the verdict (expected, unexpected or undetermined), the justification, who decided
        and when, plus the history of any changed answer. Read by the triage panel and by the
        report, which refuses to state a risk level while a signal is still unqualified.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = $Request.Query.tenantFilter ?? $Request.Body.tenantFilter
    $UserId = $Request.Query.userId ?? $Request.Body.userId

    if ([string]::IsNullOrWhiteSpace($TenantFilter) -or [string]::IsNullOrWhiteSpace($UserId)) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'tenantFilter and userId are both required.' }
            })
    }

    try {
        $Triage = Get-PSITBecTriage -TenantFilter $TenantFilter -UserId $UserId
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = $Triage
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'PSITListBecTriage' -tenant $TenantFilter -message "Failed to read BEC triage for $($UserId): $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Body       = @{ Results = "Could not read the triage: $($ErrorMessage.NormalizedError)" }
            })
    }
}
