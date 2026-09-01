Function Invoke-PSITListIpReputation {
    <#
    .FUNCTIONALITY
        Entrypoint,AnyTenant
    .ROLE
        Security.Incident.Read
    .DESCRIPTION
        The AbuseIPDB reputation of up to twenty addresses, for the chips the SOC screens show
        next to every IP. Called without tenantFilter because an address's reputation is not
        tenant data: no tenant boundary applies to it, and AnyTenant widens nothing else - the
        role gate stands. The heavy lifting (cache, private-range filtering, quota discipline)
        lives in Get-PSITIpReputation; the key never leaves the server.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint

    $Raw = $Request.Query.Ips ?? $Request.Body.Ips
    $Ips = if ($Raw -is [array]) { @($Raw) } else { @([string]$Raw -split ',') }
    $Ips = @($Ips | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ })

    if ($Ips.Count -eq 0) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'Ips is required: a comma-separated list or an array of addresses.' }
            })
    }

    try {
        $Answer = Get-PSITIpReputation -Ips $Ips
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = [pscustomobject]@{
                    Results = @($Answer.Rows)
                    Notes   = @($Answer.Notes)
                }
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API $APIName -tenant 'CIPP' -message "IP reputation lookup failed: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = "La consultation de réputation n'a pas abouti : $($ErrorMessage.NormalizedError)" }
            })
    }
}
