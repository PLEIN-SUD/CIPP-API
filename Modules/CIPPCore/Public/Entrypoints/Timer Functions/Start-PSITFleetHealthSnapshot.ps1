function Start-PSITFleetHealthSnapshot {
    <#
    .SYNOPSIS
        Records the daily fleet health figures, so the dashboard can show a trend.

    .DESCRIPTION
        The Lighthouse aggregate answers "how is the fleet right now" and nothing else: there is
        no history to query, so a machine whose protection was switched off three weeks ago and a
        fleet that went silent yesterday look identical in the live view.

        One row per tenant per day, written here. A day is the right granularity: this measures a
        managed fleet, where what matters is the direction over weeks, not the minute a signature
        version changed.

        Re-running the same day overwrites that day rather than adding a second row - the timer
        can fire twice, a node can retry, and a trend that double-counts a retry is worse than no
        trend. The row therefore keys on tenant and date.

        Failures are logged and swallowed per tenant: one client whose data cannot be read must
        not cost the other thirty-nine their history for the day.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    if (-not $PSCmdlet.ShouldProcess('Start-PSITFleetHealthSnapshot', 'Recording fleet health')) {
        return
    }

    $Today = [datetime]::UtcNow.ToString('yyyy-MM-dd')
    $Now = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')

    try {
        $Health = Get-PSITFleetHealth
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -API 'PSITFleetHealthSnapshot' -tenant 'CIPP' -message "Could not read fleet health for the daily snapshot: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return
    }

    $Table = Get-CIPPTable -tablename 'PSITFleetHealthHistory'
    $Written = 0

    foreach ($Tenant in @($Health.Tenants)) {
        try {
            $Entity = @{
                # Partitioned by tenant, keyed by day: re-running a day replaces it instead of
                # counting it twice.
                PartitionKey        = [string]$Tenant.Tenant
                RowKey              = $Today
                Date                = $Today
                RecordedUtc         = $Now
                DevicesReported     = [int]$Tenant.DevicesReported
                NeedsAttention      = [int]$Tenant.NeedsAttention
                ProtectionInDefault = [int]$Tenant.ProtectionInDefault
                ActiveThreats       = [int]$Tenant.ActiveThreats
            }
            $null = Add-CIPPAzDataTableEntity @Table -Entity $Entity -Force
            $Written++
        } catch {
            $ErrorMessage = Get-CippException -Exception $_
            Write-LogMessage -API 'PSITFleetHealthSnapshot' -tenant $Tenant.Tenant -message "Could not record the daily fleet health: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        }
    }

    Write-LogMessage -API 'PSITFleetHealthSnapshot' -tenant 'CIPP' -message "Fleet health recorded for $Written tenant(s) on $Today ($($Health.Metadata.TotalDevices) machines reported, $($Health.Metadata.NeedsAttention) needing attention)" -sev Info
}
