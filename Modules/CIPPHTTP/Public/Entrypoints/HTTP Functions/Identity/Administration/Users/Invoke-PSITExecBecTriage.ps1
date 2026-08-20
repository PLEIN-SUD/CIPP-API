Function Invoke-PSITExecBecTriage {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Identity.User.ReadWrite
    .DESCRIPTION
        Records an analyst's determination on the BEC signals that data alone cannot settle, such
        as whether a run of successful sign-ins from an unexpected country was a legitimate trip.
        Each determination is stored with the analyst's name, a UTC timestamp and an optional
        justification, and is printed in the report - which is what turns the PDF from a machine
        guess into a dated, attributable assessment.

        Writes nothing to the customer tenant: the determination lives in CIPP's own storage.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = $Request.Body.tenantFilter
    $UserId = $Request.Body.userId
    $UserPrincipalName = $Request.Body.userPrincipalName
    $Determinations = @($Request.Body.determinations)

    if ([string]::IsNullOrWhiteSpace($TenantFilter) -or [string]::IsNullOrWhiteSpace($UserId)) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'tenantFilter and userId are both required.' }
            })
    }
    if ($Determinations.Count -eq 0) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'No determination was supplied.' }
            })
    }

    $Analyst = Get-PSITBecAnalyst -Headers $Request.Headers

    try {
        $Result = Set-PSITBecTriage -TenantFilter $TenantFilter -UserId $UserId -UserPrincipalName $UserPrincipalName -Determinations $Determinations -Analyst $Analyst
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @{
                    Results = "Determination recorded by $Analyst for $(@($Determinations).Count) signal(s)."
                    Triage  = $Result
                }
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'PSITExecBecTriage' -tenant $TenantFilter -message "Failed to record BEC triage for $($UserPrincipalName ?? $UserId): $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = "Could not record the determination: $($ErrorMessage.NormalizedError)" }
            })
    }
}
