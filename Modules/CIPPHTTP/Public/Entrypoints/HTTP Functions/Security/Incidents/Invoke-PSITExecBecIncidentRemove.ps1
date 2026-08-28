Function Invoke-PSITExecBecIncidentRemove {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        SuperAdmin.ReadWrite
    .DESCRIPTION
        Deletes a BEC investigation record: the incident file and its stored determinations, both
        keyed on tenant and user. Super admin only, same rationale as the case deletion - closing
        keeps a trail, deleting is for test records and mistakes, and the deletion itself is
        logged because that is the one trace that must survive it.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = Get-PSITSocRequestValue -Value ($Request.Body.tenantFilter ?? $Request.Query.tenantFilter)
    $UserId = Get-PSITSocRequestValue -Value ($Request.Body.userId ?? $Request.Query.userId)

    if ([string]::IsNullOrWhiteSpace($TenantFilter) -or [string]::IsNullOrWhiteSpace($UserId)) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'tenantFilter and userId are required.' }
            })
    }

    try {
        $Removed = [System.Collections.Generic.List[string]]::new()
        foreach ($TableName in @('PSITBecIncidents', 'PSITBecTriage')) {
            $Table = Get-CippTable -tablename $TableName
            $Entity = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$TenantFilter' and RowKey eq '$UserId'"
            if ($Entity) {
                Remove-AzDataTableEntity @Table -Entity $Entity
                $Removed.Add($TableName)
            }
        }
        if ($Removed.Count -eq 0) {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::NotFound
                    Body       = @{ Results = "No BEC record for this user on $TenantFilter." }
                })
        }
        Write-LogMessage -headers $Request.Headers -API 'PSITExecBecIncidentRemove' -tenant $TenantFilter -message "BEC record deleted for user $UserId ($($Removed -join ', '))." -sev Alert
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @{ Results = "BEC record deleted ($($Removed -join ', ')). Only this log line remains." }
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'PSITExecBecIncidentRemove' -tenant $TenantFilter -message "Could not delete the BEC record for ${UserId}: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Body       = @{ Results = "Could not delete the BEC record: $($ErrorMessage.NormalizedError)" }
            })
    }
}
