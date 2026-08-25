function Get-PSITFleetHealth {
    <#
    .SYNOPSIS
        Defender protection state across the managed tenants, as rows and per-tenant counts.

    .DESCRIPTION
        Reads the Lighthouse managed-tenant aggregates (windowsProtectionStates and
        windowsDeviceMalwareStates) and turns them into one row per reporting machine, plus a
        count per tenant.

        Shared by the view and by the timer that records history: two copies of "what counts as
        protection in default" would drift, and the drift would show up as a dashboard and a trend
        that disagree about the same day.

        A machine appears only if Lighthouse reported it. The per-tenant DevicesReported count
        travels with the result for that reason: a fleet that stops reporting has to be visible as
        a drop, not as an absence of red rows.

    .PARAMETER Protection
        Injected protection rows. When omitted they are fetched. Injection is what makes the
        aggregation testable without Graph.

    .PARAMETER Malware
        Injected malware rows, same rationale.
    #>
    [CmdletBinding()]
    param(
        [string]$TenantFilter,

        [AllowNull()]
        $Protection,

        [AllowNull()]
        $Malware,

        [AllowNull()]
        $Tenants
    )

    if ($null -eq $Tenants) { $Tenants = Get-Tenants -IncludeErrors }
    $ByCustomerId = @{}
    foreach ($Tenant in @($Tenants)) {
        if ($Tenant.customerId) { $ByCustomerId[[string]$Tenant.customerId] = $Tenant }
    }

    if ($null -eq $Protection -or $null -eq $Malware) {
        $ProtectionBase = 'https://graph.microsoft.com/beta/tenantRelationships/managedTenants/windowsProtectionStates?$top=999'
        $MalwareBase = 'https://graph.microsoft.com/beta/tenantRelationships/managedTenants/windowsDeviceMalwareStates?$top=999'

        $CustomerId = $null
        if ($TenantFilter -and $TenantFilter -ne 'AllTenants') {
            $CustomerId = ($Tenants | Where-Object { $_.defaultDomainName -eq $TenantFilter } | Select-Object -First 1).customerId
        }

        # Reads one aggregate, and says which one when it fails. CIPP normalises several unrelated
        # Graph errors to the same sentence, so a caller that reports only the normalised text can
        # say neither which of the two calls failed nor what Graph actually answered.
        #
        # No retry without the filter: production fails identically on AllTenants, which sends no
        # filter at all, so a rejected filter is already ruled out and a second call would only
        # add a second failure to the log.
        $Fetch = {
            param($Name, $BaseUri, $Filter)

            $Uri = if ($Filter) { "$BaseUri&`$filter=tenantId eq '$Filter'" } else { $BaseUri }
            try {
                return @(New-GraphGetRequest -uri $Uri)
            } catch {
                throw "Lighthouse aggregate $Name failed. Graph said: $($_.Exception.Message)"
            }
        }

        if ($null -eq $Protection) { $Protection = & $Fetch 'windowsProtectionStates' $ProtectionBase $CustomerId }
        if ($null -eq $Malware) { $Malware = & $Fetch 'windowsDeviceMalwareStates' $MalwareBase $CustomerId }
    }

    # Active threats indexed by device, so a machine row carries what is running on it.
    $ThreatsByDevice = @{}
    foreach ($Threat in @($Malware)) {
        if ($Threat.malwareThreatState -ne 'Active') { continue }
        $Key = '{0}|{1}' -f $Threat.tenantId, $Threat.managedDeviceName
        if (-not $ThreatsByDevice.ContainsKey($Key)) {
            $ThreatsByDevice[$Key] = [System.Collections.Generic.List[object]]::new()
        }
        $ThreatsByDevice[$Key].Add($Threat)
    }

    $Results = foreach ($State in @($Protection)) {
        $Key = '{0}|{1}' -f $State.tenantId, $State.managedDeviceName
        # Where-Object, not just @(): indexing a hashtable on a missing key yields $null, and
        # @($null) has a count of one - which credited every healthy machine with a phantom
        # threat and made the whole fleet look infected.
        $Threats = @($ThreatsByDevice[$Key] | Where-Object { $_ })
        $TenantName = $ByCustomerId[[string]$State.tenantId].defaultDomainName ?? [string]$State.tenantId

        # Named here rather than derived by each caller: what counts as "protection in default" is
        # a judgement, and the view, the history and any future alert must read the same one.
        $ProtectionOff = $State.realTimeProtectionEnabled -eq $false -or $State.malwareProtectionEnabled -eq $false
        $Attention = $State.attentionRequired -eq $true

        [PSCustomObject]@{
            Tenant                         = $TenantName
            TenantId                       = [string]$State.tenantId
            DeviceName                     = [string]$State.managedDeviceName
            OsVersion                      = [string]$State.osVersion
            RealTimeProtectionEnabled      = $State.realTimeProtectionEnabled
            MalwareProtectionEnabled       = $State.malwareProtectionEnabled
            NetworkInspectionSystemEnabled = $State.networkInspectionSystemEnabled
            ManagedDeviceHealthState       = [string]$State.managedDeviceHealthState
            AttentionRequired              = $State.attentionRequired
            LastSyncDateTime               = [string]$State.lastSyncDateTime
            ProtectionInDefault            = $ProtectionOff
            ActiveThreatCount              = @($Threats).Count
            ActiveThreats                  = @($Threats | ForEach-Object { [string]$_.malwareDisplayName } | Where-Object { $_ } | Select-Object -Unique)
            NeedsAttention                 = $ProtectionOff -or $Attention -or @($Threats).Count -gt 0
        }
    }

    $Results = @($Results)
    $Reported = @(
        $Results | Group-Object -Property Tenant | ForEach-Object {
            [PSCustomObject]@{
                Tenant              = $_.Name
                DevicesReported     = $_.Count
                NeedsAttention      = @($_.Group | Where-Object { $_.NeedsAttention }).Count
                ProtectionInDefault = @($_.Group | Where-Object { $_.ProtectionInDefault }).Count
                ActiveThreats       = @($_.Group | Where-Object { $_.ActiveThreatCount -gt 0 }).Count
            }
        }
    )

    return [PSCustomObject]@{
        Results  = $Results
        Tenants  = $Reported
        Metadata = [PSCustomObject]@{
            TotalDevices   = $Results.Count
            NeedsAttention = @($Results | Where-Object { $_.NeedsAttention }).Count
            ActiveThreats  = @($Results | Where-Object { $_.ActiveThreatCount -gt 0 }).Count
            Source         = 'Lighthouse managed tenants (windowsProtectionStates, windowsDeviceMalwareStates)'
        }
    }
}
