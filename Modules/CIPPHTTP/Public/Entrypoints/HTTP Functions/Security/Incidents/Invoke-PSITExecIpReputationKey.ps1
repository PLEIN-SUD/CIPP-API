Function Invoke-PSITExecIpReputationKey {
    <#
    .FUNCTIONALITY
        Entrypoint,AnyTenant
    .ROLE
        Security.Incident.ReadWrite
    .DESCRIPTION
        Reads and writes the AbuseIPDB key, for the settings card on the ingestion screen.
        Called without tenantFilter because the key is portal configuration, not tenant data;
        AnyTenant widens nothing else. The key is validated with one live check before storage,
        never logged, and never returned - the status answer says configured or not, by whom
        and when, nothing more.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Analyst = Get-PSITBecAnalyst -Headers $Request.Headers

    try {
        # A write when the body carries Key (empty clears); a status read otherwise.
        if ($null -ne $Request.Body.Key) {
            $Outcome = Set-PSITIpReputationKey -Key ([string]$Request.Body.Key) -Analyst $Analyst
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::OK
                    Body       = @{
                        Results    = if ($Outcome.Configured) { 'Clé AbuseIPDB enregistrée (validée par une consultation).' } else { 'Clé AbuseIPDB effacée : les puces de réputation disparaissent des écrans.' }
                        Configured = [bool]$Outcome.Configured
                    }
                })
        }

        $KeyRow = Get-PSITIpReputationKey
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = [pscustomobject]@{
                    Configured = [bool]$KeyRow
                    SetUtc     = [string]$KeyRow.SetUtc
                    SetBy      = [string]$KeyRow.SetBy
                }
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API $APIName -tenant 'CIPP' -message "AbuseIPDB key operation failed: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = "L'opération sur la clé n'a pas abouti : $($ErrorMessage.NormalizedError)" }
            })
    }
}
