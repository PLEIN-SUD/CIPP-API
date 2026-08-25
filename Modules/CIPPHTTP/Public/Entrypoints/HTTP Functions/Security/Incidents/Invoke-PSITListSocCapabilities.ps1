Function Invoke-PSITListSocCapabilities {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Security.Incident.Read
    .DESCRIPTION
        Reports which SOC containment actions the tenant is licensed for, so the case view can
        show an action that will work and explain the one that will not instead of offering a
        button that answers "Invalid subscription".

        Reads the licence cache (subscribedSkus, cached a day), never the tenant live per case.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = Get-PSITSocRequestValue -Value ($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)

    if ([string]::IsNullOrWhiteSpace($TenantFilter) -or $TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'A single tenantFilter is required: licences are per tenant.' }
            })
    }

    try {
        $Capabilities = Get-PSITSocCapabilities -TenantFilter $TenantFilter
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = $Capabilities
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'PSITListSocCapabilities' -tenant $TenantFilter -message "Could not read the tenant capabilities: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Body       = @{ Results = "Could not read the capabilities: $($ErrorMessage.NormalizedError)" }
            })
    }
}
