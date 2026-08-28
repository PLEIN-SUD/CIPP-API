Function Invoke-PSITListSocAnalysts {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Security.Incident.Read
    .DESCRIPTION
        Lists the portal's users as SOC case assignment candidates: userPrincipalName and display
        name, for the queue's reassignment picker. Read-only, and deliberately not the platform's
        own user administration endpoint, which is super-admin territory: an analyst reassigning
        a case needs names, not roles.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    try {
        $Result = Get-PSITSocAnalysts
        # Analysts plus named warnings: a Graph outage degrades to email-only entries, and the
        # caller is told why the names are missing instead of being left to wonder.
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @{
                    Analysts = @($Result.Analysts)
                    Warnings = @($Result.Warnings)
                }
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'PSITListSocAnalysts' -tenant 'CIPP' -message "Failed to list the portal users: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Body       = @{ Results = "Could not list the portal users: $($ErrorMessage.NormalizedError)" }
            })
    }
}
