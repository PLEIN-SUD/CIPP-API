Function Invoke-PSITListBecIncident {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Identity.User.Read
    .DESCRIPTION
        Returns everything the incident report needs beyond the BEC collection itself: the incident
        record entered by the analyst (detection and containment times, data categories, affected
        persons, third parties warned) and the remediation trail read back from CIPP's own log, so
        the containment section states what was actually done rather than what someone remembers.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = $Request.Query.tenantFilter ?? $Request.Body.tenantFilter
    $UserId = $Request.Query.userId ?? $Request.Body.userId
    $UserPrincipalName = $Request.Query.userPrincipalName ?? $Request.Body.userPrincipalName

    if ([string]::IsNullOrWhiteSpace($TenantFilter) -or [string]::IsNullOrWhiteSpace($UserId)) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'tenantFilter and userId are both required.' }
            })
    }

    try {
        $Incident = Get-PSITBecIncident -TenantFilter $TenantFilter -UserId $UserId

        # The remediation trail is only meaningful with a mailbox name to match on; without one the
        # section is reported as unavailable rather than silently empty.
        $Remediation = if ($UserPrincipalName -or $Incident.UserPrincipalName) {
            $Since = if ($Incident.DetectedUtc) { ([datetime]$Incident.DetectedUtc).AddDays(-7) } else { [datetime]::UtcNow.AddDays(-30) }
            Get-PSITBecRemediationLog -TenantFilter $TenantFilter -UserPrincipalName ($UserPrincipalName ?? $Incident.UserPrincipalName) -UserId $UserId -SinceUtc $Since
        } else {
            [pscustomobject]@{
                Entries          = @()
                ActionsPerformed = @()
                Unavailable      = "No mailbox address was supplied, so CIPP's remediation log could not be matched to this account."
            }
        }

        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @{
                    Incident    = $Incident
                    Remediation = $Remediation
                }
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'PSITListBecIncident' -tenant $TenantFilter -message "Failed to read the incident record for $($UserId): $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Body       = @{ Results = "Could not read the incident record: $($ErrorMessage.NormalizedError)" }
            })
    }
}
