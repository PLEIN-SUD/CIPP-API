Function Invoke-PSITListSocAnalysts {
    <#
    .FUNCTIONALITY
        Entrypoint,AnyTenant
    .ROLE
        Security.Incident.Read
    .DESCRIPTION
        Lists the portal's users as SOC case assignment candidates: userPrincipalName and display
        name, for the queue's reassignment picker. Read-only, and deliberately not the platform's
        own user administration endpoint, which is super-admin territory: an analyst reassigning
        a case needs names, not roles.

        AnyTenant, and it has to be: this endpoint answers about the people who use the portal,
        not about any customer. Called without a tenantFilter - it has no tenant to filter on -
        the access check falls back to the partner tenant, which no customer-scoped role is
        allowed to see, and the whole endpoint answers 403. That is what made the queue show
        addresses where names belong, and left the reassignment picker empty. The upstream
        endpoint reading the same table declares AnyTenant for exactly this reason.

        No tenant scoping is skipped by that declaration, because there is no tenant data here:
        the list is the allowedUsers table, which is the portal's own roster.
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
