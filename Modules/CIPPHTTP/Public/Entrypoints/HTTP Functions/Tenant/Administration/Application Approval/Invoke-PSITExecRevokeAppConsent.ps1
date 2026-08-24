Function Invoke-PSITExecRevokeAppConsent {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Tenant.Application.ReadWrite
    .DESCRIPTION
        Revokes what an OAuth consent granted to an application on a tenant: disables the service
        principal, deletes its delegated permission grants, and deletes its application role
        assignments. The three steps run independently and each reports success or failure. The
        service principal itself is kept, disabled: deleting it would destroy the evidence an
        investigation still needs, and full removal stays available through ExecApplication.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = $Request.Body.tenantFilter
    $ServicePrincipalId = $Request.Body.ServicePrincipalId
    $AppId = $Request.Body.AppId

    if ([string]::IsNullOrWhiteSpace($TenantFilter)) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'tenantFilter is required.' }
            })
    }
    if ([string]::IsNullOrWhiteSpace($ServicePrincipalId) -and [string]::IsNullOrWhiteSpace($AppId)) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'ServicePrincipalId or AppId is required.' }
            })
    }

    $Analyst = Get-PSITBecAnalyst -Headers $Request.Headers

    try {
        $Revocation = Revoke-PSITAppConsent -TenantFilter $TenantFilter -ServicePrincipalId $ServicePrincipalId -AppId $AppId -Analyst $Analyst
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @{
                    Results    = @($Revocation.Results)
                    Revocation = $Revocation
                }
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'PSITExecRevokeAppConsent' -tenant $TenantFilter -message "Failed to revoke app consent: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = "Could not revoke the consent: $($ErrorMessage.NormalizedError)" }
            })
    }
}
