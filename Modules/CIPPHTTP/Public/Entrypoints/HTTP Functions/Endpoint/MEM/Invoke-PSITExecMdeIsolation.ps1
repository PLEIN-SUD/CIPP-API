Function Invoke-PSITExecMdeIsolation {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.ReadWrite
    .DESCRIPTION
        Isolates a machine from the network through Defender for Endpoint, or releases it. The
        endpoint keeps running and stays reachable by Defender; nothing else gets in or out. Full
        isolation is used rather than selective, which would still allow Outlook and Teams
        traffic. Matched to the Defender machine record by Entra device id, on the same API path
        upstream already uses to offboard a device.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = $Request.Body.tenantFilter
    $AzureADDeviceId = $Request.Body.AzureADDeviceId
    $Comment = $Request.Body.Comment
    $Release = $Request.Body.Release -eq $true

    if ([string]::IsNullOrWhiteSpace($TenantFilter) -or [string]::IsNullOrWhiteSpace($AzureADDeviceId)) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'tenantFilter and AzureADDeviceId are both required.' }
            })
    }

    $Analyst = Get-PSITBecAnalyst -Headers $Request.Headers

    try {
        $Parameters = @{
            AzureADDeviceId = $AzureADDeviceId
            TenantFilter    = $TenantFilter
            Analyst         = $Analyst
            Comment         = $Comment
        }
        if ($Release) { $Parameters.Release = $true }
        $Isolation = Set-PSITMdeIsolation @Parameters

        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @{
                    Results   = @($Isolation.Results)
                    Isolation = $Isolation
                }
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'PSITExecMdeIsolation' -tenant $TenantFilter -message "Failed to change isolation for device $($AzureADDeviceId): $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = "Could not change the isolation state: $($ErrorMessage.NormalizedError)" }
            })
    }
}
