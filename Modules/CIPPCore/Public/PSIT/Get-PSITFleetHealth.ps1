function Get-PSITFleetHealth {
    <#
    .SYNOPSIS
        Defender protection state for one tenant, as rows and counts.

    .DESCRIPTION
        Reads Intune's managed devices with their windowsProtectionState expanded, in the customer
        tenant's own context, and turns them into one row per reporting machine plus a count for
        the tenant.

        This replaces the Lighthouse managed-tenant aggregates. Those answered one call for every
        tenant at once, which was the appeal, but they are evaluated in the partner tenant and are
        refused there on this tenancy: every read, filtered or not, came back as "Request not
        applicable to target tenant". The per-tenant read costs one call per client and works,
        which beats one call that does not. It is the same route as the upstream ListDefenderState
        endpoint, so it is a route already exercised in production.

        Scope: one tenant. A fleet-wide view is assembled from the daily snapshots rather than by
        fanning out forty live calls behind a page load.

        A machine appears only if Intune reported it, and only if it carries a Windows protection
        state. Machines without one are counted separately rather than dropped in silence: an
        absence has to be visible as an absence, never as a healthy row.

    .PARAMETER Devices
        Injected managed devices. When omitted they are fetched. Injection is what makes the
        aggregation testable without Graph.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,

        [AllowNull()]
        $Devices
    )

    if ([string]::IsNullOrWhiteSpace($TenantFilter) -or $TenantFilter -eq 'AllTenants') {
        throw 'Get-PSITFleetHealth reads one tenant at a time: pass a single tenantFilter.'
    }

    if ($null -eq $Devices) {
        # Same shape as the upstream ListDefenderState endpoint, plus the two fields a fleet view
        # needs that a single-device view does not: the OS build and when the machine last synced.
        $Uri = 'https://graph.microsoft.com/beta/deviceManagement/managedDevices?$expand=windowsProtectionState&$select=id,deviceName,operatingSystem,osVersion,lastSyncDateTime,windowsProtectionState&$top=999'
        try {
            $Devices = @(New-GraphGetRequest -uri $Uri -tenantid $TenantFilter)
        } catch {
            throw "Could not read managed devices for $TenantFilter. Graph said: $($_.Exception.Message)"
        }
    }

    $Devices = @($Devices)
    # Devices Intune knows about but that report no Windows protection state: anything not
    # Windows, and Windows machines that have never reported one. Counted, not silently dropped.
    $WithoutState = @($Devices | Where-Object { $null -eq $_.windowsProtectionState })

    $Results = foreach ($Device in @($Devices | Where-Object { $null -ne $_.windowsProtectionState })) {
        $State = $Device.windowsProtectionState

        # Named here rather than derived by each caller: what counts as "protection in default" is
        # a judgement, and the view, the history and any future alert must read the same one.
        $ProtectionOff = $State.realTimeProtectionEnabled -eq $false -or $State.malwareProtectionEnabled -eq $false
        $SignatureOverdue = $State.signatureUpdateOverdue -eq $true
        $Attention = $State.attentionRequired -eq $true

        [PSCustomObject]@{
            Tenant                         = $TenantFilter
            DeviceId                       = [string]$Device.id
            DeviceName                     = [string]$Device.deviceName
            OperatingSystem                = [string]$Device.operatingSystem
            OsVersion                      = [string]$Device.osVersion
            LastSyncDateTime               = [string]$Device.lastSyncDateTime
            RealTimeProtectionEnabled      = $State.realTimeProtectionEnabled
            MalwareProtectionEnabled       = $State.malwareProtectionEnabled
            NetworkInspectionSystemEnabled = $State.networkInspectionSystemEnabled
            TamperProtectionEnabled        = $State.tamperProtectionEnabled
            SignatureVersion               = [string]$State.signatureVersion
            SignatureUpdateOverdue         = $SignatureOverdue
            ManagedDeviceHealthState       = [string]$State.deviceState
            AttentionRequired              = $Attention
            ProtectionInDefault            = $ProtectionOff
            NeedsAttention                 = $ProtectionOff -or $Attention -or $SignatureOverdue
        }
    }

    $Results = @($Results)

    return [PSCustomObject]@{
        Results = $Results
        Tenant  = [PSCustomObject]@{
            Tenant              = $TenantFilter
            DevicesReported     = $Results.Count
            NeedsAttention      = @($Results | Where-Object { $_.NeedsAttention }).Count
            ProtectionInDefault = @($Results | Where-Object { $_.ProtectionInDefault }).Count
            SignatureOverdue    = @($Results | Where-Object { $_.SignatureUpdateOverdue }).Count
            WithoutProtectionState = $WithoutState.Count
        }
        Metadata = [PSCustomObject]@{
            TotalDevices           = $Results.Count
            NeedsAttention         = @($Results | Where-Object { $_.NeedsAttention }).Count
            ProtectionInDefault    = @($Results | Where-Object { $_.ProtectionInDefault }).Count
            SignatureOverdue       = @($Results | Where-Object { $_.SignatureUpdateOverdue }).Count
            WithoutProtectionState = $WithoutState.Count
            Source                 = 'Intune managed devices with windowsProtectionState expanded'
        }
    }
}
