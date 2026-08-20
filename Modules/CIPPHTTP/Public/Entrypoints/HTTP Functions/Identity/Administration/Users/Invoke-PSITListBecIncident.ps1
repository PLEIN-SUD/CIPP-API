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

        # The remediation trail is read only once a case file exists. This endpoint is called on
        # every BEC page load, and the trail is a scan of CippLogs partitions: running it for a
        # mailbox nobody has opened a case on cost consumption for a section that reads
        # "non attestée" either way. Opening the case file (saving the Autotask ticket) is the
        # signal that the trail is wanted.
        $Mailbox = if ($UserPrincipalName) { $UserPrincipalName } else { [string]$Incident.UserPrincipalName }
        $Remediation = if (-not $Incident.Exists) {
            [pscustomobject]@{
                Entries          = @()
                ActionsPerformed = @()
                Unavailable      = "No case file has been opened for this mailbox, so CIPP's remediation log was not read. Save the case file to have the containment trail attached."
            }
        } elseif ([string]::IsNullOrWhiteSpace($Mailbox)) {
            [pscustomobject]@{
                Entries          = @()
                ActionsPerformed = @()
                Unavailable      = "No mailbox address was supplied, so CIPP's remediation log could not be matched to this account."
            }
        } else {
            $Since = if ($Incident.DetectedUtc) { ([datetime]$Incident.DetectedUtc).AddDays(-2) } else { [datetime]::UtcNow.AddDays(-7) }
            Get-PSITBecRemediationLog -TenantFilter $TenantFilter -UserPrincipalName $Mailbox -UserId $UserId -SinceUtc $Since
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
