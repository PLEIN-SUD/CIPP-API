Function Invoke-PSITListSocMetrics {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Security.Incident.Read
    .DESCRIPTION
        The steering numbers over the SOC dossiers: counts by verdict, status, severity, type and
        tenant, a monthly series, and the median delays (creation to take, to verdict, to
        closure). Same access rules as the case list: tenantFilter absent or AllTenants measures
        the whole queue, narrowed to the tenants the caller is allowed to see, so a restricted
        role's numbers only ever describe its own tenants. StartUtc/EndUtc bound the measured
        period on the dossiers' creation time — the monthly client report asks for one month, the
        steering screen for a semester.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = $Request.Query.tenantFilter
    $Parameters = @{}
    if (-not [string]::IsNullOrWhiteSpace($TenantFilter) -and $TenantFilter -ne 'AllTenants') {
        $Parameters.TenantFilter = $TenantFilter
    }

    $ParseBound = {
        param($Value)
        if ([string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
        try { return [datetime]::Parse([string]$Value, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal) } catch { return $null }
    }
    $StartUtc = & $ParseBound $Request.Query.StartUtc
    $EndUtc = & $ParseBound $Request.Query.EndUtc

    try {
        # Narrow before measuring: the aggregation must never see a tenant the caller cannot.
        $Cases = @(Get-PSITSocCase @Parameters | Select-CippAllowedTenantData -TenantProperty 'Tenant')
        if ($StartUtc -or $EndUtc) {
            $Cases = @($Cases | Where-Object {
                    $Created = $null
                    try { $Created = [datetime]::Parse([string]$_.CreatedUtc, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal) } catch { $Created = $null }
                    if (-not $Created) { return $false }
                    if ($StartUtc -and $Created -lt $StartUtc) { return $false }
                    if ($EndUtc -and $Created -ge $EndUtc) { return $false }
                    return $true
                })
        }

        $Metrics = Get-PSITSocMetrics -Cases $Cases
        $Metrics | Add-Member -NotePropertyName 'Window' -NotePropertyValue ([pscustomobject]@{
                Tenant   = if ($Parameters.TenantFilter) { [string]$Parameters.TenantFilter } else { 'AllTenants' }
                StartUtc = if ($StartUtc) { $StartUtc.ToString('o') } else { '' }
                EndUtc   = if ($EndUtc) { $EndUtc.ToString('o') } else { '' }
            }) -Force

        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = $Metrics
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'PSITListSocMetrics' -tenant $TenantFilter -message "Failed to compute SOC metrics: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Body       = @{ Results = "Les indicateurs n'ont pas pu être calculés : $($ErrorMessage.NormalizedError)" }
            })
    }
}
