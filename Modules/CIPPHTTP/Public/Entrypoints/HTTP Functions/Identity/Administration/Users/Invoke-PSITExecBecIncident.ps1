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

        With action = 'close', archives the open case instead of updating it and frees the slot for
        the next one, so a second compromise of the same mailbox cannot inherit the first one's
        reference, dates or determinations.

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

    if ([string]$Body.action -eq 'close') {
        try {
            $Closure = Close-PSITBecIncident -TenantFilter $Body.tenantFilter -UserId $Body.userId -Analyst $Analyst -ClosureNote $Body.closureNote
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::OK
                    Body       = @{
                        Results = if ($Closure.Closed) {
                            "Incident $($Closure.Reference) closed and archived by $Analyst. The next save will open a new case."
                        } else {
                            $Closure.Reason
                        }
                        Closure = $Closure
                    }
                })
        } catch {
            $ErrorMessage = Get-CippException -Exception $_
            Write-LogMessage -headers $Request.Headers -API 'PSITExecBecIncident' -tenant $Body.tenantFilter -message "Failed to close the incident record for $($Body.userPrincipalName ?? $Body.userId): $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::BadRequest
                    Body       = @{ Results = "Could not close the incident record: $($ErrorMessage.NormalizedError)" }
                })
        }
    }

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
            'deliveredTo', 'deliveredUtc', 'deliveryChannel', 'acknowledgedBy', 'acknowledgedUtc',
            'followUpDecision', 'followUpDecisionUtc',
            'tlp', 'effectDescription', 'effectDescriptionOther', 'relatedTickets'
        )) {
        $Value = $Body.$Field
        # An empty string is not a value: the panel sends '' for every field the analyst has not
        # filled, and four of the target parameters carry a ValidateSet that rejects '' outright -
        # which failed the whole save because one optional field was untouched. Omitting a blank
        # is also exactly what Set-PSITBecIncident does with one internally (blank means keep),
        # so nothing is lost by not sending it.
        if ($null -eq $Value) { continue }
        if ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value)) { continue }
        # Set-PSITBecIncident uses PascalCase parameter names.
        $Parameters[($Field.Substring(0, 1).ToUpperInvariant() + $Field.Substring(1))] = $Value
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
