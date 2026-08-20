Function Invoke-PSITExecBecIncident {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Identity.User.ReadWrite
    .DESCRIPTION
        Opens or updates the incident record of a confirmed mailbox compromise: detection and
        containment times, status, the categories of personal data and data subjects the mailbox
        held, an approximate count, whether mail reading can be established, likely consequences,
        actions taken outside CIPP and third parties warned. These are the facts a GDPR article
        33(3) description requires and that no API can supply.

        Writes nothing to the customer tenant.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $Body = $Request.Body
    if ([string]::IsNullOrWhiteSpace($Body.tenantFilter) -or [string]::IsNullOrWhiteSpace($Body.userId)) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'tenantFilter and userId are both required.' }
            })
    }

    $Analyst = Get-PSITBecAnalyst -Headers $Request.Headers

    $Parameters = @{
        TenantFilter = $Body.tenantFilter
        UserId       = $Body.userId
        Analyst      = $Analyst
    }
    foreach ($Field in @(
            'userPrincipalName', 'reference', 'autotaskTicket', 'detectedUtc', 'containedUtc', 'status',
            'dataSubjectCategories', 'dataCategories', 'affectedPersonsEstimate',
            'affectedPersonsBasis', 'mailReadStatus', 'likelyConsequences', 'executiveNote',
            'externalActions', 'thirdPartiesNotified',
            'deliveredTo', 'deliveredUtc', 'deliveryChannel', 'acknowledgedBy', 'acknowledgedUtc'
        )) {
        if ($null -ne $Body.$Field) {
            # Set-PSITBecIncident uses PascalCase parameter names.
            $Parameters[($Field.Substring(0, 1).ToUpperInvariant() + $Field.Substring(1))] = $Body.$Field
        }
    }

    try {
        $Incident = Set-PSITBecIncident @Parameters
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @{
                    Results  = "Incident record $($Incident.Reference) saved by $Analyst."
                    Incident = $Incident
                }
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'PSITExecBecIncident' -tenant $Body.tenantFilter -message "Failed to save the incident record for $($Body.userPrincipalName ?? $Body.userId): $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = "Could not save the incident record: $($ErrorMessage.NormalizedError)" }
            })
    }
}
