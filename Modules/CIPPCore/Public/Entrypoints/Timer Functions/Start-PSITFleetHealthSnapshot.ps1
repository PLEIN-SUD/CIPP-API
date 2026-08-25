function Start-PSITFleetHealthSnapshot {
    <#
    .SYNOPSIS
        Records the daily fleet health figures per tenant, and the machines worth looking at.

    .DESCRIPTION
        Two jobs, both of which exist because the source is now read one tenant at a time.

        History: the live read answers "how is this fleet right now" and nothing else, so a
        machine whose protection was switched off three weeks ago and a fleet that went silent
        yesterday look identical in it. One row per tenant per day fixes that.

        Fleet-wide view: forty live Graph calls behind a page load is not a page load. The
        multi-tenant screen therefore reads the most recent snapshot instead, which is why the row
        also carries the machines needing attention and not only the counts.

        Re-running the same day overwrites that day rather than adding a second row, since the
        timer can fire twice and a node can retry. The row keys on tenant and date.

        Failures are logged and swallowed per tenant: one client whose data cannot be read must
        not cost the others their history for the day.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    if (-not $PSCmdlet.ShouldProcess('Start-PSITFleetHealthSnapshot', 'Recording fleet health')) {
        return
    }

    $Today = [datetime]::UtcNow.ToString('yyyy-MM-dd')
    $Now = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')

    try {
        $Tenants = @(Get-Tenants)
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -API 'PSITFleetHealthSnapshot' -tenant 'CIPP' -message "Could not list the tenants for the daily snapshot: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return
    }

    $Table = Get-CIPPTable -tablename 'PSITFleetHealthHistory'
    $Written = 0
    $Failed = 0
    $TotalDevices = 0
    $TotalAttention = 0

    foreach ($Tenant in $Tenants) {
        $TenantName = [string]$Tenant.defaultDomainName
        if ([string]::IsNullOrWhiteSpace($TenantName)) { continue }

        try {
            $Health = Get-PSITFleetHealth -TenantFilter $TenantName
        } catch {
            $Failed++
            $ErrorMessage = Get-CippException -Exception $_
            Write-LogMessage -API 'PSITFleetHealthSnapshot' -tenant $TenantName -message "Could not read fleet health: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
            continue
        }

        try {
            $Attention = @($Health.Results | Where-Object { $_.NeedsAttention })
            # Capped so one very unhealthy client cannot overrun the entity property limit and
            # cost every other client its row. The flag travels with the data: a truncated list
            # that says nothing about being truncated is a list that reads as complete.
            $Truncated = $Attention.Count -gt 100
            $Stored = @($Attention | Select-Object -First 100 | Select-Object Tenant, DeviceName, OperatingSystem, OsVersion, LastSyncDateTime,
                RealTimeProtectionEnabled, MalwareProtectionEnabled, SignatureUpdateOverdue, AttentionRequired, ProtectionInDefault, NeedsAttention,
                ManagedDeviceHealthState)

            $Entity = @{
                # Partitioned by tenant, keyed by day: re-running a day replaces it instead of
                # counting it twice.
                PartitionKey           = $TenantName
                RowKey                 = $Today
                Date                   = $Today
                RecordedUtc            = $Now
                DevicesReported        = [int]$Health.Tenant.DevicesReported
                NeedsAttention         = [int]$Health.Tenant.NeedsAttention
                ProtectionInDefault    = [int]$Health.Tenant.ProtectionInDefault
                SignatureOverdue       = [int]$Health.Tenant.SignatureOverdue
                WithoutProtectionState = [int]$Health.Tenant.WithoutProtectionState
                AttentionDevices       = ([string](ConvertTo-Json -InputObject $Stored -Depth 3 -Compress))
                AttentionTruncated     = [bool]$Truncated
            }
            $null = Add-CIPPAzDataTableEntity @Table -Entity $Entity -Force
            $Written++
            $TotalDevices += [int]$Health.Tenant.DevicesReported
            $TotalAttention += [int]$Health.Tenant.NeedsAttention
        } catch {
            $Failed++
            $ErrorMessage = Get-CippException -Exception $_
            Write-LogMessage -API 'PSITFleetHealthSnapshot' -tenant $TenantName -message "Could not record the daily fleet health: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        }
    }

    # The failure count is in the summary on purpose: a snapshot covering thirty of forty clients
    # is not a snapshot of the fleet, and the trend drawn from it would not say so on its own.
    Write-LogMessage -API 'PSITFleetHealthSnapshot' -tenant 'CIPP' -message "Fleet health recorded for $Written of $($Tenants.Count) tenants on $Today, $Failed failed. $TotalDevices machines reported, $TotalAttention needing attention." -sev Info
}
