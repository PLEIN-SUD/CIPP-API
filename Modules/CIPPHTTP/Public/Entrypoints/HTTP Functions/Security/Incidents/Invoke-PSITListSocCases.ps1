Function Invoke-PSITListSocCases {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Security.Incident.Read
    .DESCRIPTION
        Lists the SOC triage cases: alerts adopted from Defender XDR or Defender for Office 365,
        or typed in from an external SOC notification, each carrying its qualification, its guide
        progress and its action log. Filterable by tenant, case id, status, source and external
        reference. tenantFilter=AllTenants (or absent) returns the whole queue, narrowed to the
        tenants the caller is allowed to see.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = $Request.Query.tenantFilter
    $Parameters = @{}
    if (-not [string]::IsNullOrWhiteSpace($TenantFilter)) { $Parameters.TenantFilter = $TenantFilter }
    foreach ($Name in @('CaseId', 'Status', 'Source', 'ExternalRef')) {
        $Value = $Request.Query.$Name
        if (-not [string]::IsNullOrWhiteSpace($Value)) { $Parameters.$Name = $Value }
    }

    try {
        # The allowed-tenant narrowing applies on every path, not only AllTenants: it is a no-op
        # for an unrestricted caller and closes the gap for a tenant-restricted custom role.
        $Cases = @(Get-PSITSocCase @Parameters | Select-CippAllowedTenantData -TenantProperty 'Tenant')
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @($Cases)
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'PSITListSocCases' -tenant $TenantFilter -message "Failed to list SOC cases: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Body       = @{ Results = "Could not list the SOC cases: $($ErrorMessage.NormalizedError)" }
            })
    }
}
