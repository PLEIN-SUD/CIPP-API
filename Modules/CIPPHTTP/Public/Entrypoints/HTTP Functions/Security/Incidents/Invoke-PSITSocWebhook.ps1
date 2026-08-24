Function Invoke-PSITSocWebhook {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Public
    .DESCRIPTION
        Ingestion endpoint for the SOC case queue: the automation that already turns an external
        SOC notification into a ticket posts the same facts here, and the case exists without
        anyone retyping it.

        Public means unauthenticated by CIPP's RBAC, so authorisation is a shared secret carried
        in the query string, compared against the one stored by ExecSocWebhookSecret. No secret
        generated means the endpoint refuses everything: an unauthenticated endpoint that creates
        records must fail closed, never open.

        The tenant is resolved from the name the caller supplies, against the managed tenant list.
        When it cannot be resolved unambiguously the case is filed under 'unmapped' rather than
        under a guess: an analyst reassigns it from the queue, where a case filed under the wrong
        client would simply never be found.

        Body: Source, TypeId, Title, and optionally Severity, ExternalRef, TicketRef, TenantFilter
        or TenantName, and Entities. Adoption stays idempotent through Set-PSITSocCase, so the
        automation retrying costs nothing.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $Deny = ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::Forbidden
            Body       = @{ Results = 'This webhook is not authorized.' }
        })

    $Supplied = [string]($Request.Query.secret ?? $Request.Headers.'x-psit-soc-secret')
    if ([string]::IsNullOrWhiteSpace($Supplied)) { return $Deny }

    $Configured = Get-PSITSocWebhookSecret
    if (-not $Configured -or [string]::IsNullOrWhiteSpace($Configured.Secret)) {
        Write-LogMessage -API 'PSITSocWebhook' -tenant 'CIPP' -message 'SOC webhook called while no secret is configured: refused.' -sev Warn
        return $Deny
    }
    # -ceq: a case-insensitive comparison would accept a secret that is not the secret.
    if ($Supplied -cne $Configured.Secret) {
        Write-LogMessage -API 'PSITSocWebhook' -tenant 'CIPP' -message 'SOC webhook called with an invalid secret: refused.' -sev Warn
        return $Deny
    }

    $Body = $Request.Body
    if (-not $Body) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'A body is required.' }
            })
    }

    try {
        $Tenants = Get-Tenants -IncludeErrors
        $Resolution = if (-not [string]::IsNullOrWhiteSpace($Body.TenantFilter)) {
            Resolve-PSITSocTenant -Name $Body.TenantFilter -Tenants $Tenants
        } else {
            Resolve-PSITSocTenant -Name $Body.TenantName -Tenants $Tenants
        }

        $Parameters = @{
            TenantFilter = $Resolution.Tenant
            Analyst      = 'webhook'
            Source       = if ([string]::IsNullOrWhiteSpace($Body.Source)) { 'extsoc' } else { [string]$Body.Source }
            Title        = [string]$Body.Title
        }
        if ($null -ne $Body.TypeId -and "$($Body.TypeId)" -match '^\d+$') {
            $Parameters.TypeId = [int]$Body.TypeId
        }
        foreach ($Name in @('Severity', 'ExternalRef', 'TicketRef')) {
            if (-not [string]::IsNullOrWhiteSpace($Body.$Name)) { $Parameters.$Name = [string]$Body.$Name }
        }
        if ($null -ne $Body.Entities) { $Parameters.Entities = $Body.Entities }

        $Case = Set-PSITSocCase @Parameters

        # How the tenant was decided travels with the case: an analyst seeing 'unmapped' must be
        # able to tell "the name matched nothing" from "two clients matched".
        $null = Set-PSITSocCase -TenantFilter $Case.Tenant -CaseId $Case.CaseId -Analyst 'webhook' -LogAction @{
            Action = 'ingested'
            Detail = "Tenant resolution: $($Resolution.Method) from '$($Body.TenantName ?? $Body.TenantFilter)'"
        }

        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @{
                    Results          = "SOC case $($Case.CaseId) ingested."
                    CaseId           = $Case.CaseId
                    Tenant           = $Case.Tenant
                    TenantResolution = $Resolution.Method
                }
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -API 'PSITSocWebhook' -tenant 'CIPP' -message "Failed to ingest a SOC case: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = "Could not ingest the case: $($ErrorMessage.NormalizedError)" }
            })
    }
}
