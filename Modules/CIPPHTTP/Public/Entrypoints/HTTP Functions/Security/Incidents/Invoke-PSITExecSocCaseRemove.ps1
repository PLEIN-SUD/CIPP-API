Function Invoke-PSITExecSocCaseRemove {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        SuperAdmin.ReadWrite
    .DESCRIPTION
        Deletes a SOC case outright. Super admin only, and deliberately not part of the analyst
        vocabulary: an analyst closes a case, which keeps its journal; deleting is for test
        records and mistakes, and it removes the trail with the row. The deletion itself is
        logged, since the one trace that must survive a deletion is that it happened.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = Get-PSITSocRequestValue -Value ($Request.Body.tenantFilter ?? $Request.Query.tenantFilter)
    $CaseId = Get-PSITSocRequestValue -Value ($Request.Body.CaseId ?? $Request.Query.CaseId)

    if ([string]::IsNullOrWhiteSpace($TenantFilter) -or [string]::IsNullOrWhiteSpace($CaseId)) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'tenantFilter and CaseId are required.' }
            })
    }

    try {
        $Table = Get-CippTable -tablename 'PSITSocCases'
        $Entity = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$TenantFilter' and RowKey eq '$CaseId'"
        if (-not $Entity) {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::NotFound
                    Body       = @{ Results = "No case $CaseId on $TenantFilter." }
                })
        }
        Remove-AzDataTableEntity @Table -Entity $Entity
        Write-LogMessage -headers $Request.Headers -API 'PSITExecSocCaseRemove' -tenant $TenantFilter -message "SOC case $CaseId deleted." -sev Alert
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @{ Results = "SOC case $CaseId deleted. This removed its journal as well: only this log line remains." }
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'PSITExecSocCaseRemove' -tenant $TenantFilter -message "Could not delete SOC case ${CaseId}: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Body       = @{ Results = "Could not delete the case: $($ErrorMessage.NormalizedError)" }
            })
    }
}
