Function Invoke-PSITListMaliciousApps {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Tenant.Application.Read
    .DESCRIPTION
        Returns the known-malicious application catalogue CIPP ships (Config/MaliciousApps.json):
        the list the BEC collection already matches applications against. Exposed so the SOC
        dashboard can answer "is this application in the catalogue" on the case itself, instead of
        sending the analyst to read a file in the repository.

        Nothing tenant-specific here: it is a static list, returned as it ships. Matching against
        a tenant's applications stays with the caller, which is what lets the case answer the
        question in place.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    try {
        $Path = Join-Path $env:CIPPRootPath 'Config\MaliciousApps.json'
        $Catalogue = @((Get-Content -Path $Path -ErrorAction Stop | ConvertFrom-Json).applications)

        # Only what an analyst needs to decide on a case: naming the app, saying what it does, and
        # linking to why it is listed. The full entry stays in the file for the collection.
        $Results = foreach ($Application in $Catalogue) {
            [PSCustomObject]@{
                Name        = [string]$Application.name
                AppId       = [string]$Application.appId
                Description = [string]$Application.description
                Categories  = @($Application.categories)
                Publisher   = [string]$Application.publisher
                References  = @($Application.references)
            }
        }

        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @($Results)
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'PSITListMaliciousApps' -message "Could not read the malicious application catalogue: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        # An unreadable catalogue must not read as an empty one: a case would then answer "not in
        # the catalogue" about an application nobody checked.
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Body       = @{ Results = "Could not read the catalogue: $($ErrorMessage.NormalizedError)" }
            })
    }
}
