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

    # Unwrapped: an application picked from an autocomplete arrives as {label, value}, and a
    # raw read would look up an object instead of an appId.
    $TenantFilter = Get-PSITSocRequestValue -Value $Request.Body.tenantFilter
    $ServicePrincipalId = Get-PSITSocRequestValue -Value $Request.Body.ServicePrincipalId
    $AppId = Get-PSITSocRequestValue -Value $Request.Body.AppId
    $CaseId = Get-PSITSocRequestValue -Value $Request.Body.CaseId

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

        # Written here rather than left to the caller: the grants are gone the moment this returns,
        # and a second call the browser might fail to make would lose them for good. A dossier is
        # named only when the revocation was run from one.
        if (-not [string]::IsNullOrWhiteSpace($CaseId)) {
            try {
                $null = Set-PSITSocCase -TenantFilter $TenantFilter -CaseId $CaseId -Analyst $Analyst -Evidence @{
                    app = [pscustomobject]@{
                        displayName     = $Revocation.DisplayName
                        appId           = $Revocation.AppId
                        publisherName   = $Revocation.PublisherName
                        createdDateTime = $Revocation.CreatedDateTime
                        removedGrants   = @($Revocation.RemovedGrants)
                        revokedUtc      = $Revocation.RevokedUtc
                    }
                }
            } catch {
                # The revocation itself succeeded; failing to file its evidence is worth a log and
                # not a failed response, which would read as "nothing was revoked".
                Write-LogMessage -headers $Request.Headers -API 'PSITExecRevokeAppConsent' -tenant $TenantFilter -message "Consent revoked but its evidence could not be filed on case ${CaseId}: $($_.Exception.Message)" -sev Warn
            }
        }

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
