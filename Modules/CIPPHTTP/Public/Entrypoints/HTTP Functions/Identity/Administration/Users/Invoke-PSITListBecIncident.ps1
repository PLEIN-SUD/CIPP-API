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
                Unavailable      = "Le journal de remédiation CIPP n'a pas encore été lu : il est attaché à la fiche BEC, et aucune fiche n'est enregistrée pour cette boîte. Enregistrer la fiche déclenche la lecture, y compris pour des gestes déjà faits."
            }
        } elseif ([string]::IsNullOrWhiteSpace($Mailbox)) {
            [pscustomobject]@{
                Entries          = @()
                ActionsPerformed = @()
                Unavailable      = "Aucune adresse de boîte n'a été fournie : le journal de remédiation CIPP ne peut pas être rapproché de ce compte."
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
