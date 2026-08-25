Function Invoke-PSITListMailEvidence {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Security.Incident.Read
    .DESCRIPTION
        What Defender knows about the message a case is about: sender, subject, verdict, and one
        line per recipient saying where that copy sits now.

        The case view offered a purge button and nothing else, which asked an analyst to delete a
        message he could not see. This is the evidence that button was missing.

        Reads through Get-PSITMailEvidence, the same function the purge reads through, so the
        panel and the action can never disagree about what was found.

        Needs Defender for Office 365 Plan 2, like the purge. A tenant without it gets an empty
        answer saying so, rather than an error the analyst has to interpret.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = Get-PSITSocRequestValue -Value $Request.Query.tenantFilter
    $NetworkMessageId = Get-PSITSocRequestValue -Value $Request.Query.NetworkMessageId
    $ReceivedUtc = Get-PSITSocRequestValue -Value $Request.Query.ReceivedUtc

    if ([string]::IsNullOrWhiteSpace($TenantFilter) -or $TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'A single tenantFilter is required.' }
            })
    }
    if ([string]::IsNullOrWhiteSpace($NetworkMessageId)) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'NetworkMessageId is required.' }
            })
    }

    try {
        $Evidence = Get-PSITMailEvidence -TenantFilter $TenantFilter -NetworkMessageId $NetworkMessageId -ReceivedUtc $ReceivedUtc
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = $Evidence
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'PSITListMailEvidence' -tenant $TenantFilter -message "Could not read the message evidence: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Body       = @{ Results = "Could not read the message evidence: $($ErrorMessage.NormalizedError)" }
            })
    }
}
