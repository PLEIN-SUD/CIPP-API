Function Invoke-PSITListFleetHealth {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.Read
    .DESCRIPTION
        Defender health across every managed tenant, in one view: which machines have their
        protection off or behind, and which are carrying an active malware threat.

        The data comes from the Lighthouse managed-tenant aggregates
        (windowsProtectionStates and windowsDeviceMalwareStates) that CIPP already reads inside
        its Defender alerts. Reading them as a view rather than as an alert is the whole point:
        the Defender portal answers this per tenant, and nobody answers it across forty. That
        cross-tenant question is the one an MSP actually has.

        Rows are narrowed to the tenants the caller may see: the Lighthouse aggregate returns
        every managed tenant with no per-caller scoping, exactly as ListAllTenantDeviceCompliance
        documents.

        A machine appears here only if Lighthouse knows it, which means it is onboarded and
        reporting. A silent machine is therefore an absence, not a green row: the response says
        how many machines each tenant reported so a fleet that stopped reporting is visible as a
        drop rather than as good news.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = $Request.Query.tenantFilter
    $Headers = $Request.Headers

    try {
        $Tenants = Get-Tenants -IncludeErrors
        $ByCustomerId = @{}
        foreach ($Tenant in @($Tenants)) {
            if ($Tenant.customerId) { $ByCustomerId[[string]$Tenant.customerId] = $Tenant }
        }

        $ProtectionUri = 'https://graph.microsoft.com/beta/tenantRelationships/managedTenants/windowsProtectionStates?$top=999'
        $MalwareUri = 'https://graph.microsoft.com/beta/tenantRelationships/managedTenants/windowsDeviceMalwareStates?$top=999'

        # A single tenant still goes through the aggregate rather than through Intune: one source
        # means one set of field names and one behaviour, whichever scope the page asks for.
        if ($TenantFilter -and $TenantFilter -ne 'AllTenants') {
            $CustomerId = ($Tenants | Where-Object { $_.defaultDomainName -eq $TenantFilter } | Select-Object -First 1).customerId
            if ($CustomerId) {
                $ProtectionUri = "$ProtectionUri&`$filter=tenantId eq '$CustomerId'"
                $MalwareUri = "$MalwareUri&`$filter=tenantId eq '$CustomerId'"
            }
        }

        $Protection = @(New-GraphGetRequest -uri $ProtectionUri | Select-CippAllowedTenantData -TenantProperty 'tenantId')
        $Malware = @(New-GraphGetRequest -uri $MalwareUri | Select-CippAllowedTenantData -TenantProperty 'tenantId')

        # Active threats indexed by device, so a machine row can carry what is running on it.
        $ThreatsByDevice = @{}
        foreach ($Threat in $Malware) {
            if ($Threat.malwareThreatState -ne 'Active') { continue }
            $Key = '{0}|{1}' -f $Threat.tenantId, $Threat.managedDeviceName
            if (-not $ThreatsByDevice.ContainsKey($Key)) {
                $ThreatsByDevice[$Key] = [System.Collections.Generic.List[object]]::new()
            }
            $ThreatsByDevice[$Key].Add($Threat)
        }

        $Results = foreach ($State in $Protection) {
            $Key = '{0}|{1}' -f $State.tenantId, $State.managedDeviceName
            $Threats = @($ThreatsByDevice[$Key])
            $TenantName = $ByCustomerId[[string]$State.tenantId].defaultDomainName ?? [string]$State.tenantId

            # Named rather than derived in the frontend: what counts as "protection in default" is
            # a judgement, and it belongs in one place both the view and any future alert can read.
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
                # One row is worth an analyst's attention when the protection is off, the device
                # asks for attention, or something is running on it.
                NeedsAttention                 = $ProtectionOff -or $Attention -or @($Threats).Count -gt 0
            }
        }

        $Results = @($Results)
        # Reported counts per tenant: a fleet that stops reporting shows as a drop here rather
        # than as an absence of red rows.
        $Reported = @(
            $Results | Group-Object -Property Tenant | ForEach-Object {
                [PSCustomObject]@{
                    Tenant          = $_.Name
                    DevicesReported = $_.Count
                    NeedsAttention  = @($_.Group | Where-Object { $_.NeedsAttention }).Count
                }
            }
        )

        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @{
                    Results  = $Results
                    Tenants  = $Reported
                    Metadata = @{
                        TotalDevices   = $Results.Count
                        NeedsAttention = @($Results | Where-Object { $_.NeedsAttention }).Count
                        ActiveThreats  = @($Results | Where-Object { $_.ActiveThreatCount -gt 0 }).Count
                        Source         = 'Lighthouse managed tenants (windowsProtectionStates, windowsDeviceMalwareStates)'
                    }
                }
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API 'PSITListFleetHealth' -tenant $TenantFilter -message "Could not read fleet health: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        # Never an empty list on failure: a dashboard that shows nothing because the call failed
        # reads exactly like a fleet in perfect health.
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Body       = @{ Results = "Could not read fleet health: $($ErrorMessage.NormalizedError)" }
            })
    }
}
