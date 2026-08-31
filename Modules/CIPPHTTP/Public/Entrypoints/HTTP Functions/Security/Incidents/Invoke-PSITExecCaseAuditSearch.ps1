Function Invoke-PSITExecCaseAuditSearch {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Tenant.Alert.ReadWrite
    .DESCRIPTION
        The audit search behind a role-change, inbox-rule or mailbox-access dossier (types 4, 5
        and 7): reads the one the dossier already has, starts one when asked. Same contract as
        the download search endpoint: reading and starting are separate verbs (the panel polls,
        and a poll must never open a search), starting is idempotent through the dossier's
        Evidence.audit, a relaunch keeps the search it replaces, and the summary is captured on
        the dossier at the first finished read because the search expires with the journal.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $TenantFilter = Get-PSITSocRequestValue -Value ($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
    $CaseId = Get-PSITSocRequestValue -Value ($Request.Query.CaseId ?? $Request.Body.CaseId)
    $HoursBefore = Get-PSITSocRequestValue -Value ($Request.Query.HoursBefore ?? $Request.Body.HoursBefore)
    $Start = Get-PSITSocRequestValue -Value ($Request.Query.Start ?? $Request.Body.Start)
    $Restart = Get-PSITSocRequestValue -Value ($Request.Query.Restart ?? $Request.Body.Restart)

    if ([string]::IsNullOrWhiteSpace($TenantFilter) -or [string]::IsNullOrWhiteSpace($CaseId)) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'tenantFilter and CaseId are both required.' }
            })
    }

    $Wants = ("$Start" -eq 'true' -or $Start -eq $true -or "$Restart" -eq 'true' -or $Restart -eq $true)
    $WantsRestart = ("$Restart" -eq 'true' -or $Restart -eq $true)

    try {
        $Case = @(Get-PSITSocCase -TenantFilter $TenantFilter -CaseId $CaseId) | Select-Object -First 1
        if (-not $Case) {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::NotFound
                    Body       = @{ Results = "Dossier $CaseId introuvable sur ce tenant." }
                })
        }
        if (-not (Get-PSITAuditSearchKind -TypeId ([int]$Case.TypeId))) {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::BadRequest
                    Body       = @{ Results = "Ce type de dossier n'a pas de recherche d'audit définie." }
                })
        }

        $Filed = $Case.Evidence.audit
        $SearchId = if ($WantsRestart) { '' } else { [string]$Filed.searchId }

        if ([string]::IsNullOrWhiteSpace($SearchId)) {
            if (-not $Wants) {
                return ([HttpResponseContext]@{
                        StatusCode = [HttpStatusCode]::OK
                        Body       = [pscustomobject]@{ Started = $false; Running = $false; Records = @(); Summary = $null; Warnings = @() }
                    })
            }

            $Upn = [string]$Case.Entities.upn
            if ([string]::IsNullOrWhiteSpace($Upn)) {
                return ([HttpResponseContext]@{
                        StatusCode = [HttpStatusCode]::BadRequest
                        Body       = @{ Results = "Ce dossier ne nomme aucun utilisateur : renseignez l'UPN pour lancer la recherche." }
                    })
            }

            $Anchor = if ([string]::IsNullOrWhiteSpace([string]$Case.CreatedUtc)) { '' } else { [string]$Case.CreatedUtc }
            $Analyst = Get-PSITBecAnalyst -Headers $Request.Headers
            $StartParameters = @{
                TenantFilter      = $TenantFilter
                TypeId            = [int]$Case.TypeId
                UserPrincipalName = $Upn
                CaseId            = $CaseId
                Analyst           = $Analyst
                AroundUtc         = $Anchor
            }
            if ($HoursBefore -and "$HoursBefore" -match '^\d+$') { $StartParameters.HoursBefore = [int]$HoursBefore }
            if ($WantsRestart -and $Case.Evidence.audit) { $StartParameters.Previous = $Case.Evidence.audit }
            $Started = Start-PSITCaseAuditSearch @StartParameters

            $null = Set-PSITSocCase -TenantFilter $TenantFilter -CaseId $CaseId -Analyst $Analyst -LogAction @{
                Action = 'audit-search'
                Detail = "Recherche d'audit ($($Started.Kind)) lancée pour $Upn du $(([datetime]$Started.StartUtc).ToString('dd/MM/yyyy HH:mm')) au $(([datetime]$Started.EndUtc).ToString('dd/MM/yyyy HH:mm')) UTC (recherche $($Started.SearchId))."
            }
            Write-LogMessage -headers $Request.Headers -API $APIName -tenant $TenantFilter -message "Case audit search $($Started.SearchId) started for case $CaseId" -sev Info
            $SearchId = $Started.SearchId
            $Filed = [pscustomobject]@{
                kind        = $Started.Kind
                searchId    = $Started.SearchId
                user        = $Upn
                startUtc    = $Started.StartUtc
                endUtc      = $Started.EndUtc
                launchedUtc = $Started.LaunchedUtc
                launchedBy  = $Analyst
            }
        }

        $Result = Get-PSITCaseAuditSearch -TenantFilter $TenantFilter -SearchId $SearchId

        # First finished read: the summary outlives the search (same custody as the downloads).
        if (-not $Result.Running -and $null -ne $Result.Summary -and $null -eq $Filed.summary) {
            try {
                $Captured = [pscustomobject]@{}
                foreach ($Property in ([pscustomobject]$Filed).PSObject.Properties) {
                    $Captured | Add-Member -NotePropertyName $Property.Name -NotePropertyValue $Property.Value
                }
                $Captured | Add-Member -NotePropertyName 'summary' -NotePropertyValue $Result.Summary -Force
                $Captured | Add-Member -NotePropertyName 'capturedUtc' -NotePropertyValue ((Get-Date).ToUniversalTime().ToString('o')) -Force
                $null = Set-PSITSocCase -TenantFilter $TenantFilter -CaseId $CaseId -Analyst (Get-PSITBecAnalyst -Headers $Request.Headers) -Evidence @{ audit = $Captured }
                $Filed = $Captured
            } catch {
                Write-LogMessage -headers $Request.Headers -API $APIName -tenant $TenantFilter -message "Case audit summary could not be filed on case $($CaseId): $($_.Exception.Message)" -sev Warn
            }
        }

        $Result | Add-Member -NotePropertyName 'Started' -NotePropertyValue $true -Force
        $Result | Add-Member -NotePropertyName 'Window' -NotePropertyValue ([pscustomobject]@{
                Kind        = [string]$Filed.kind
                User        = [string]$Filed.user
                StartUtc    = [string]$Filed.startUtc
                EndUtc      = [string]$Filed.endUtc
                LaunchedUtc = [string]$Filed.launchedUtc
                LaunchedBy  = [string]$Filed.launchedBy
            }) -Force

        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = $Result
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API $APIName -tenant $TenantFilter -message "Could not run the case audit search for $($CaseId): $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = "La recherche n'a pas pu aboutir : $($ErrorMessage.NormalizedError)" }
            })
    }
}
