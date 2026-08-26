Function Invoke-PSITListSocDevices {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.Read
    .DESCRIPTION
        Every machine Intune or Defender for Endpoint knows in the tenant, joined on the Entra
        device id, each row saying who manages it. Feeds the device picker: reading Intune alone
        made MDE-only machines unselectable, and therefore uninvestigable, from this portal.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = Get-PSITSocRequestValue -Value $Request.Query.tenantFilter
    if ([string]::IsNullOrWhiteSpace($TenantFilter) -or $TenantFilter -eq 'AllTenants') {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'A single tenantFilter is required.' }
            })
    }

    try {
        $Devices = Get-PSITSocDevices -TenantFilter $TenantFilter
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = $Devices
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'PSITListSocDevices' -tenant $TenantFilter -message "Could not list the devices: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Body       = @{ Results = "Could not list the devices: $($ErrorMessage.Message)" }
            })
    }
}
