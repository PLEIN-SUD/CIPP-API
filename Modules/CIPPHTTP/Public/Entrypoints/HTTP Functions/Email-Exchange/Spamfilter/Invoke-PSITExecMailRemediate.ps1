Function Invoke-PSITExecMailRemediate {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Exchange.SpamFilter.ReadWrite
    .DESCRIPTION
        Soft-deletes a delivered malicious message from the mailboxes that received it: what an
        incomplete ZAP leaves to do. The message is moved to Deleted Items for the recipients
        named, through the Defender analyzedEmails remediation API. Soft delete, never hard
        delete: a purge decided wrongly stays recoverable and the evidence survives. Requires
        Defender for Office 365 Plan 2 on the tenant.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    # Unwrapped: recipients picked from a multi-select arrive as {label, value} entries, and a
    # raw read would purge nothing while claiming a recipient list.
    $TenantFilter = Get-PSITSocRequestValue -Value $Request.Body.tenantFilter
    $NetworkMessageId = Get-PSITSocRequestValue -Value $Request.Body.NetworkMessageId
    $Recipients = @(Get-PSITSocRequestValue -Value $Request.Body.Recipients | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $ReceivedUtc = Get-PSITSocRequestValue -Value $Request.Body.ReceivedUtc
    $CaseId = Get-PSITSocRequestValue -Value $Request.Body.CaseId

    if ([string]::IsNullOrWhiteSpace($TenantFilter) -or [string]::IsNullOrWhiteSpace($NetworkMessageId)) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'tenantFilter and NetworkMessageId are both required.' }
            })
    }

    $Analyst = Get-PSITBecAnalyst -Headers $Request.Headers

    try {
        $Remediation = Invoke-PSITMailRemediation -TenantFilter $TenantFilter -NetworkMessageId $NetworkMessageId -Recipients $Recipients -ReceivedUtc $ReceivedUtc -Analyst $Analyst

        # Filed here rather than left to the caller: the message is deleted the moment this
        # returns, and a second call the browser might fail to make would lose who received it.
        if (-not [string]::IsNullOrWhiteSpace($CaseId) -and $null -ne $Remediation.EvidenceBefore) {
            try {
                $null = Set-PSITSocCase -TenantFilter $TenantFilter -CaseId $CaseId -Analyst $Analyst -Evidence @{
                    mail = $Remediation.EvidenceBefore
                }
            } catch {
                # The purge succeeded; failing to file its evidence is worth a log and not a
                # failed response, which would read as "nothing was purged".
                Write-LogMessage -headers $Request.Headers -API 'PSITExecMailRemediate' -tenant $TenantFilter -message "Message purged but its evidence could not be filed on case ${CaseId}: $($_.Exception.Message)" -sev Warn
            }
        }

        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @{
                    Results     = @($Remediation.Results)
                    Remediation = $Remediation
                }
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'PSITExecMailRemediate' -tenant $TenantFilter -message "Failed to remediate message $($NetworkMessageId): $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = "Could not remediate the message: $($ErrorMessage.NormalizedError)" }
            })
    }
}
