Function Invoke-PSITListFleetHealth {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.Read
    .DESCRIPTION
        Defender protection state across the managed fleet: which machines have their protection
        off or their signatures behind, and which clients are affected.

        One tenant is read live, one Graph call, in that tenant's own context. The whole fleet is
        read from the daily snapshots instead, because forty live calls behind a page load is not
        a page load. The response says which of the two it is and how old it is, since a snapshot
        presented as the present is a wrong answer rather than a slow one.

        A machine appears here only if Intune reported it. The response therefore carries how many
        machines each tenant reported, so a fleet that stopped reporting shows up as a drop rather
        than as an absence of red rows.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = Get-PSITSocRequestValue -Value $Request.Query.tenantFilter
    $Headers = $Request.Headers

    try {
        if ($TenantFilter -and $TenantFilter -ne 'AllTenants') {
            $Health = Get-PSITFleetHealth -TenantFilter $TenantFilter
            $Results = @($Health.Results | Select-CippAllowedTenantData -TenantProperty 'Tenant')
            $Tenants = @($Health.Tenant | Where-Object { $_.Tenant -in @($Results.Tenant) })

            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::OK
                    Body       = @{
                        Results  = $Results
                        Tenants  = $Tenants
                        Metadata = @{
                            TotalDevices           = $Results.Count
                            NeedsAttention         = @($Results | Where-Object { $_.NeedsAttention }).Count
                            ProtectionInDefault    = @($Results | Where-Object { $_.ProtectionInDefault }).Count
                            SignatureOverdue       = @($Results | Where-Object { $_.SignatureUpdateOverdue }).Count
                            WithoutProtectionState = $Health.Metadata.WithoutProtectionState
                            Source                 = $Health.Metadata.Source
                            Live                   = $true
                            AsOf                   = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
                        }
                    }
                })
        }

        # Whole fleet: the most recent snapshot per tenant. Bounded to the last week so the scan
        # stays small; a tenant whose last snapshot is older than that has stopped being recorded
        # and its absence is the finding.
        $Table = Get-CIPPTable -tablename 'PSITFleetHealthHistory'
        $Since = [datetime]::UtcNow.AddDays(-7).ToString('yyyy-MM-dd')
        $Rows = @(Get-CIPPAzDataTableEntity @Table | Where-Object { [string]$_.RowKey -ge $Since })
        $Rows = @($Rows | Select-CippAllowedTenantData -TenantProperty 'PartitionKey')

        $Latest = @(
            $Rows | Group-Object -Property PartitionKey | ForEach-Object {
                $_.Group | Sort-Object -Property RowKey -Descending | Select-Object -First 1
            }
        )

        $Results = foreach ($Row in $Latest) {
            if ([string]::IsNullOrWhiteSpace([string]$Row.AttentionDevices)) { continue }
            try {
                $Devices = @([string]$Row.AttentionDevices | ConvertFrom-Json)
            } catch {
                # A row whose payload cannot be read is skipped, not treated as a tenant with
                # nothing wrong: the counts below still come from the row's own figures.
                Write-Information "PSITListFleetHealth: unreadable AttentionDevices for $($Row.PartitionKey) on $($Row.RowKey)"
                continue
            }
            foreach ($Device in $Devices) {
                $Device | Add-Member -NotePropertyName 'SnapshotDate' -NotePropertyValue ([string]$Row.RowKey) -Force
                $Device
            }
        }
        $Results = @($Results)

        $Tenants = @(
            $Latest | ForEach-Object {
                [PSCustomObject]@{
                    Tenant                 = [string]$_.PartitionKey
                    DevicesReported        = [int]$_.DevicesReported
                    NeedsAttention         = [int]$_.NeedsAttention
                    ProtectionInDefault    = [int]$_.ProtectionInDefault
                    SignatureOverdue       = [int]$_.SignatureOverdue
                    WithoutProtectionState = [int]$_.WithoutProtectionState
                    SnapshotDate           = [string]$_.RowKey
                    AttentionTruncated     = [bool]$_.AttentionTruncated
                }
            }
        )

        $AsOf = if ($Tenants.Count -gt 0) { @($Tenants.SnapshotDate | Sort-Object -Descending)[0] } else { '' }

        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @{
                    Results  = $Results
                    Tenants  = $Tenants
                    Metadata = @{
                        TotalDevices           = ($Tenants | Measure-Object -Property DevicesReported -Sum).Sum ?? 0
                        NeedsAttention         = ($Tenants | Measure-Object -Property NeedsAttention -Sum).Sum ?? 0
                        ProtectionInDefault    = ($Tenants | Measure-Object -Property ProtectionInDefault -Sum).Sum ?? 0
                        SignatureOverdue       = ($Tenants | Measure-Object -Property SignatureOverdue -Sum).Sum ?? 0
                        WithoutProtectionState = ($Tenants | Measure-Object -Property WithoutProtectionState -Sum).Sum ?? 0
                        TenantsReporting       = $Tenants.Count
                        Source                 = 'Daily snapshot of Intune managed devices'
                        Live                   = $false
                        AsOf                   = $AsOf
                    }
                }
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Headers -API 'PSITListFleetHealth' -tenant $TenantFilter -message "Could not read fleet health: $($ErrorMessage.Message)" -sev Error -LogData $ErrorMessage
        # Never an empty list on failure: a dashboard that shows nothing because the call failed
        # reads exactly like a fleet in perfect health.
        #
        # The raw message is returned rather than the normalised one. Get-NormalizedError maps
        # several distinct Graph answers onto a single sentence, which is fine for an action a
        # user retries and useless for a read that has to be diagnosed.
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Body       = @{ Results = "Could not read fleet health: $($ErrorMessage.Message)" }
            })
    }
}
