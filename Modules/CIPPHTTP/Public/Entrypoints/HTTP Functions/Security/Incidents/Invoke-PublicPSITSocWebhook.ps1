Function Invoke-PublicPSITSocWebhook {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Public
    .DESCRIPTION
        Ingestion endpoint for the SOC case queue: the automation that already turns an external
        SOC notification into a ticket posts the same facts here, and the case exists without
        anyone retyping it.

        The Public name prefix is what exposes it: the static web app only routes /api/Public*
        anonymously, and the function app behind it refuses everything else at the platform door
        before any code runs. Renamed after a live call answered 401 from that door.

        Public means unauthenticated by CIPP's RBAC, so authorisation is a shared secret carried
        in the query string, compared against the one stored by ExecSocWebhookSecret. No secret
        generated means the endpoint refuses everything: an unauthenticated endpoint that creates
        records must fail closed, never open.

        The tenant is resolved from the name the caller supplies, against the managed tenant list,
        and the two ways that can fail are answered differently.

        A name matching two clients is filed under 'unmapped' rather than under a guess: an
        analyst reassigns it from the queue, where a case filed under the wrong client would
        simply never be found.

        A name matching nothing at all opens no case, and the response says so. This portal only
        knows Microsoft tenants, so a name it has never seen is, in practice, a client managed
        somewhere else: opening a case for it would put a row in the queue that no screen here can
        investigate, every time that client raises an alert, until the analyst learns to skip
        those rows. The caller is told the tenant is unknown and decides what to do with its own
        ticket. The refusal is logged with the name, so a genuine typo on a managed client is
        visible rather than lost.

        Post the raw Subject and the rest follows: the alert type, the client scope and the
        affected entity are read from it here, so the automation never has to reproduce a mapping
        table nor keep it in step with this one. An explicit TypeId, TenantName or Title still
        wins over what the subject says, for a caller that already knows better.

        An alert this portal cannot investigate opens no case, for the same reason an unknown
        client does not: a row nobody can act on teaches an analyst to skip rows.

        Body: Subject, or Source, TypeId and Title supplied directly. Optionally Severity,
        ExternalRef, TicketRef, TenantFilter or TenantName, and Entities. Adoption stays
        idempotent through Set-PSITSocCase, so the automation retrying costs nothing.
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
        # Parsed first: the subject carries the client scope, which is what the tenant resolves
        # from when the caller names none.
        $Alert = Resolve-PSITSocAlertType -Subject ([string]$Body.Subject)

        if ($Alert.OutOfScope) {
            Write-LogMessage -API 'PSITSocWebhook' -tenant 'CIPP' -message "SOC webhook: '$($Alert.LabelId)' is out of scope for this portal, no case opened." -sev Info
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::OK
                    Body       = @{
                        Results  = "$($Alert.Reason) No case was opened."
                        Ingested = $false
                        Reason   = 'out-of-scope'
                        LabelId  = $Alert.LabelId
                    }
                })
        }

        # CompanyName joins the candidates: the automation resolves its PSA company before it
        # calls here, and that name usually matches the tenant displayName. One more chance to
        # land on the right client instead of answering unknown-tenant.
        $TenantName = @($Body.TenantFilter, $Body.TenantName, $Alert.Scope, $Body.CompanyName) |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -First 1

        $Tenants = Get-Tenants -IncludeErrors
        $Resolution = Resolve-PSITSocTenant -Name $TenantName -Tenants $Tenants

        if ($Resolution.Reason -eq 'unknown') {
            $Supplied = [string]$TenantName
            Write-LogMessage -API 'PSITSocWebhook' -tenant 'CIPP' -message "SOC webhook: no managed tenant matches '$Supplied', no case opened." -sev Warn
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::OK
                    Body       = @{
                        Results          = "No managed tenant matches '$Supplied': no case was opened. This portal only covers Microsoft tenants."
                        Ingested         = $false
                        Reason           = 'unknown-tenant'
                        TenantResolution = $Resolution.Method
                    }
                })
        }

        $Parameters = @{
            TenantFilter = $Resolution.Tenant
            Analyst      = 'webhook'
            Source       = if ([string]::IsNullOrWhiteSpace($Body.Source)) { 'extsoc' } else { [string]$Body.Source }
            # The label read off the subject, when the caller sends no title of its own.
            Title        = if ([string]::IsNullOrWhiteSpace($Body.Title)) { [string]$Alert.Label } else { [string]$Body.Title }
        }
        if ($null -ne $Body.TypeId -and "$($Body.TypeId)" -match '^\d+$') {
            $Parameters.TypeId = [int]$Body.TypeId
        } elseif ($Alert.TypeId -gt 0) {
            $Parameters.TypeId = [int]$Alert.TypeId
        }
        if (-not [string]::IsNullOrWhiteSpace($Alert.DetectionSource)) {
            $Parameters.DetectionSource = [string]$Alert.DetectionSource
        }
        foreach ($Name in @('Severity', 'SeverityTag', 'ExternalRef', 'TicketRef', 'TicketUrl')) {
            if (-not [string]::IsNullOrWhiteSpace($Body.$Name)) { $Parameters.$Name = [string]$Body.$Name }
        }
        # 'Unknown' is the automation's word for "the mail named no priority": an absence, not a
        # tag. Stored, it would shadow forever a Severity set by hand on the case, because the
        # queue shows the emitter's tag over the P level whenever one exists.
        if ($Parameters['SeverityTag'] -eq 'Unknown') { $null = $Parameters.Remove('SeverityTag') }
        if ($null -ne $Body.Entities) {
            $Parameters.Entities = $Body.Entities
        } elseif (-not [string]::IsNullOrWhiteSpace($Alert.Target)) {
            # The subject names one entity, and which kind depends on the alert: a mail address
            # for the identity labels, a machine name for the endpoint ones.
            $Parameters.Entities = if ($Alert.Target -like '*@*') {
                @{ upn = [string]$Alert.Target }
            } else {
                @{ deviceName = [string]$Alert.Target }
            }
        }

        $Case = Set-PSITSocCase @Parameters

        # How the tenant was decided travels with the case: an analyst seeing 'unmapped' must be
        # able to tell "the name matched nothing" from "two clients matched".
        $null = Set-PSITSocCase -TenantFilter $Case.Tenant -CaseId $Case.CaseId -Analyst 'webhook' -LogAction @{
            Action = 'ingested'
            Detail = "Tenant resolution: $($Resolution.Method) from '$TenantName'. Alert label: $($Alert.LabelId) ($($Alert.Status)).$(if ($Alert.EmitterTicket) { " Emitter ticket #$($Alert.EmitterTicket)." })"
        }

        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @{
                    Results          = "SOC case $($Case.CaseId) ingested."
                    Ingested         = $true
                    CaseId           = $Case.CaseId
                    Tenant           = $Case.Tenant
                    TenantResolution = $Resolution.Method
                    LabelId          = $Alert.LabelId
                    TypeId           = $Case.TypeId
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
