Function Invoke-PSITExecSocWebhookSecret {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Security.Incident.ReadWrite
    .DESCRIPTION
        Reads or rotates the shared secret that authorises the SOC ingestion webhook. Rotating
        invalidates the previous secret immediately, so the automation posting cases has to be
        updated in the same move. Until a secret exists the webhook refuses every call.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $Rotate = ($Request.Query.rotate ?? $Request.Body.rotate) -eq $true
    $Analyst = Get-PSITBecAnalyst -Headers $Request.Headers

    try {
        if ($Rotate) {
            $Secret = Set-PSITSocWebhookSecret -Analyst $Analyst
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::OK
                    Body       = @{
                        Results = 'A new secret was generated. The previous one no longer works: update the automation that posts cases.'
                        Secret  = $Secret.Secret
                        RotatedUtc = $Secret.RotatedUtc
                    }
                })
        }

        $Existing = Get-PSITSocWebhookSecret
        if (-not $Existing) {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::OK
                    Body       = @{
                        Results    = 'No secret generated yet: the ingestion webhook refuses every call until one exists.'
                        Configured = $false
                    }
                })
        }

        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @{
                    Results    = "Secret in place, rotated $($Existing.RotatedUtc) by $($Existing.RotatedBy)."
                    Configured = $true
                    Secret     = $Existing.Secret
                    RotatedUtc = $Existing.RotatedUtc
                }
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'PSITExecSocWebhookSecret' -tenant 'CIPP' -message "Failed to read or rotate the SOC webhook secret: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = "Could not read or rotate the secret: $($ErrorMessage.NormalizedError)" }
            })
    }
}
