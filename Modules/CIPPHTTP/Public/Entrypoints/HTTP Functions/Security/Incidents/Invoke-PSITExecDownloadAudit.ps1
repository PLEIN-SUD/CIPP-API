Function Invoke-PSITExecDownloadAudit {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Tenant.Alert.ReadWrite
    .DESCRIPTION
        The audit search behind a mass-download dossier: reads the one the dossier already has,
        and starts one when asked.

        Reading and starting are separate on purpose. The panel polls this endpoint every few
        seconds while a search runs, and a read that could create a search would create one on
        every poll of a dossier whose search was never filed. So a call without Start only
        reports, and answers Started=false when the dossier has no search yet.

        Starting is idempotent all the same: the search id is filed on the dossier, and a Start on
        a dossier that already has one returns that search rather than opening a second. Audit
        searches take minutes, the panel is opened more than once, and two searches for one
        dossier would leave a report unable to say which one its numbers came from.

        Tenant.Alert.ReadWrite because that is what creating an audit search costs upstream; the
        dossier itself is only written to record which search answers for it.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $TenantFilter = Get-PSITSocRequestValue -Value ($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
    $CaseId = Get-PSITSocRequestValue -Value ($Request.Query.CaseId ?? $Request.Body.CaseId)
    $UserPrincipalName = Get-PSITSocRequestValue -Value ($Request.Query.UserPrincipalName ?? $Request.Body.UserPrincipalName)
    $AroundUtc = Get-PSITSocRequestValue -Value ($Request.Query.AroundUtc ?? $Request.Body.AroundUtc)
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

        $Filed = $Case.Evidence.download
        $SearchId = if ($WantsRestart) { '' } else { [string]$Filed.searchId }

        if ([string]::IsNullOrWhiteSpace($SearchId)) {
            if (-not $Wants) {
                # Nothing filed and nobody asked to start: say so, rather than opening a search on
                # a poll the analyst never triggered.
                return ([HttpResponseContext]@{
                        StatusCode = [HttpStatusCode]::OK
                        Body       = [pscustomobject]@{ Started = $false; Running = $false; Records = @(); Summary = $null; Warnings = @() }
                    })
            }

            $Upn = if ([string]::IsNullOrWhiteSpace($UserPrincipalName)) { [string]$Case.Entities.upn } else { $UserPrincipalName }
            if ([string]::IsNullOrWhiteSpace($Upn)) {
                return ([HttpResponseContext]@{
                        StatusCode = [HttpStatusCode]::BadRequest
                        Body       = @{ Results = "Ce dossier ne nomme aucun utilisateur : renseignez l'UPN pour lancer la recherche." }
                    })
            }

            # The alert's own hour, not the hour the dossier was opened: a dossier picked up the
            # next morning would otherwise search a day when nothing happened.
            $Anchor = if ([string]::IsNullOrWhiteSpace($AroundUtc)) { [string]$Case.CreatedUtc } else { $AroundUtc }
            $Analyst = Get-PSITBecAnalyst -Headers $Request.Headers
            $StartParameters = @{
                TenantFilter      = $TenantFilter
                UserPrincipalName = $Upn
                CaseId            = $CaseId
                Analyst           = $Analyst
                AroundUtc         = $Anchor
            }
            if ($WantsRestart -and $Case.Evidence.download) { $StartParameters.Previous = $Case.Evidence.download }
            if ($HoursBefore -and "$HoursBefore" -match '^\d+$') { $StartParameters.HoursBefore = [int]$HoursBefore }
            $Started = Start-PSITDownloadAudit @StartParameters

            $null = Set-PSITSocCase -TenantFilter $TenantFilter -CaseId $CaseId -Analyst $Analyst -LogAction @{
                Action = 'audit-search'
                Detail = "Recherche des téléchargements de $Upn lancée dans le journal d'audit du $(([datetime]$Started.StartUtc).ToString('dd/MM/yyyy HH:mm')) au $(([datetime]$Started.EndUtc).ToString('dd/MM/yyyy HH:mm')) UTC (recherche $($Started.SearchId))."
            }
            Write-LogMessage -headers $Request.Headers -API $APIName -tenant $TenantFilter -message "Download audit search $($Started.SearchId) started for case $CaseId" -sev Info
            $SearchId = $Started.SearchId
            $Filed = [pscustomobject]@{
                searchId    = $Started.SearchId
                user        = $Upn
                startUtc    = $Started.StartUtc
                endUtc      = $Started.EndUtc
                launchedUtc = $Started.LaunchedUtc
                launchedBy  = $Analyst
            }
        }

        $Result = Get-PSITDownloadAudit -TenantFilter $TenantFilter -SearchId $SearchId

        # First successful read: the summary is captured on the dossier. The search and its
        # records expire with the tenant's audit journal, and the investigation report quotes
        # these numbers - they must outlive their source. A capture that fails logs and moves on:
        # the analyst still gets the live answer.
        if (-not $Result.Running -and $null -ne $Result.Summary -and $null -eq $Filed.summary) {
            try {
                $Captured = [pscustomobject]@{}
                foreach ($Property in ([pscustomobject]$Filed).PSObject.Properties) {
                    $Captured | Add-Member -NotePropertyName $Property.Name -NotePropertyValue $Property.Value
                }
                $Captured | Add-Member -NotePropertyName 'summary' -NotePropertyValue $Result.Summary -Force
                $Captured | Add-Member -NotePropertyName 'capturedUtc' -NotePropertyValue ((Get-Date).ToUniversalTime().ToString('o')) -Force
                $null = Set-PSITSocCase -TenantFilter $TenantFilter -CaseId $CaseId -Analyst (Get-PSITBecAnalyst -Headers $Request.Headers) -Evidence @{ download = $Captured }
                $Filed = $Captured
            } catch {
                Write-LogMessage -headers $Request.Headers -API $APIName -tenant $TenantFilter -message "Download audit summary could not be filed on case $($CaseId): $($_.Exception.Message)" -sev Warn
            }
        }

        # The window travels with the answer: a file count means nothing without the hours it
        # counts over, and the report quotes both.
        $Result | Add-Member -NotePropertyName 'Started' -NotePropertyValue $true -Force
        $Result | Add-Member -NotePropertyName 'Window' -NotePropertyValue ([pscustomobject]@{
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
        Write-LogMessage -headers $Request.Headers -API $APIName -tenant $TenantFilter -message "Could not run the download audit for case $($CaseId): $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = "La recherche n'a pas pu aboutir : $($ErrorMessage.NormalizedError)" }
            })
    }
}
