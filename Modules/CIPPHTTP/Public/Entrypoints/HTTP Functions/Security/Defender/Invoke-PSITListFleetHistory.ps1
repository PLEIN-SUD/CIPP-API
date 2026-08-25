Function Invoke-PSITListFleetHistory {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.Read
    .DESCRIPTION
        The recorded daily fleet health figures: one row per tenant per day, written by the
        Start-PSITFleetHealthSnapshot timer.

        The Lighthouse aggregate only answers for the present, so without this a protection
        switched off three weeks ago and a fleet that went silent yesterday look the same. Reading
        the history is what separates them.

        Days with no row are days the snapshot did not run, and are absent rather than zero: a
        zero would read as "nothing wrong that day".
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = $Request.Query.tenantFilter
    $Days = if ($Request.Query.days -match '^\d+$') { [int]$Request.Query.days } else { 30 }
    if ($Days -gt 365) { $Days = 365 }

    try {
        $Table = Get-CIPPTable -tablename 'PSITFleetHealthHistory'
        $Since = [datetime]::UtcNow.AddDays(-$Days).ToString('yyyy-MM-dd')

        $Rows = if ($TenantFilter -and $TenantFilter -ne 'AllTenants') {
            Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$TenantFilter'"
        } else {
            Get-CIPPAzDataTableEntity @Table
        }

        $Rows = @($Rows | Where-Object { [string]$_.RowKey -ge $Since })
        # Same narrowing as the live view: the history is per tenant, and a tenant-restricted
        # caller must not read another client's trend.
        $Rows = @($Rows | Select-CippAllowedTenantData -TenantProperty 'PartitionKey')

        $Results = foreach ($Row in $Rows) {
            [PSCustomObject]@{
                Tenant              = [string]$Row.PartitionKey
                Date                = [string]$Row.RowKey
                RecordedUtc         = [string]$Row.RecordedUtc
                DevicesReported     = [int]$Row.DevicesReported
                NeedsAttention      = [int]$Row.NeedsAttention
                ProtectionInDefault = [int]$Row.ProtectionInDefault
                ActiveThreats       = [int]$Row.ActiveThreats
            }
        }
        $Results = @($Results | Sort-Object -Property Date)

        # Totals per day across the tenants read, which is what a trend line needs.
        $Daily = @(
            $Results | Group-Object -Property Date | ForEach-Object {
                [PSCustomObject]@{
                    Date                = $_.Name
                    TenantsReporting    = $_.Count
                    DevicesReported     = ($_.Group | Measure-Object -Property DevicesReported -Sum).Sum
                    NeedsAttention      = ($_.Group | Measure-Object -Property NeedsAttention -Sum).Sum
                    ProtectionInDefault = ($_.Group | Measure-Object -Property ProtectionInDefault -Sum).Sum
                    ActiveThreats       = ($_.Group | Measure-Object -Property ActiveThreats -Sum).Sum
                }
            } | Sort-Object -Property Date
        )

        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @{
                    Results = $Results
                    Daily   = $Daily
                    Metadata = @{
                        Days       = $Days
                        DaysWithData = $Daily.Count
                    }
                }
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'PSITListFleetHistory' -tenant $TenantFilter -message "Could not read fleet history: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Body       = @{ Results = "Could not read fleet history: $($ErrorMessage.NormalizedError)" }
            })
    }
}
