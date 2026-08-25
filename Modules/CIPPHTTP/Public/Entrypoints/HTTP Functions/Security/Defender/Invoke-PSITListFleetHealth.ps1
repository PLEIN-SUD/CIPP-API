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
        (windowsProtectionStates and windowsDeviceMalwareStates), which CIPP already reads inside
        its Defender alerts: one Graph call covers every tenant, with no per-tenant fan-out.

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
        # The aggregation lives in Get-PSITFleetHealth so the view and the daily snapshot read the
        # same definition of "protection in default"; rows are then narrowed to the tenants this
        # caller may see, since the Lighthouse aggregate returns every managed tenant.
        $Health = Get-PSITFleetHealth -TenantFilter $TenantFilter
        $Results = @($Health.Results | Select-CippAllowedTenantData -TenantProperty 'TenantId')
        $Allowed = @($Results | ForEach-Object { $_.Tenant } | Select-Object -Unique)
        $Reported = @($Health.Tenants | Where-Object { $Allowed -contains $_.Tenant })

        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @{
                    Results  = $Results
                    Tenants  = $Reported
                    Metadata = @{
                        TotalDevices   = $Results.Count
                        NeedsAttention = @($Results | Where-Object { $_.NeedsAttention }).Count
                        ActiveThreats  = @($Results | Where-Object { $_.ActiveThreatCount -gt 0 }).Count
                        Source         = $Health.Metadata.Source
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
        # user retries and useless for a read that has to be diagnosed: 'Required license not
        # available for this tenant' hides both which aggregate failed and what Graph replied.
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Body       = @{ Results = "Could not read fleet health: $($ErrorMessage.Message)" }
            })
    }
}
