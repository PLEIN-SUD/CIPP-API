function Start-PSITCaseEnrichment {
    <#
    .SYNOPSIS
        Pre-fills a freshly ingested dossier, from the cippqueue.

    .DESCRIPTION
        The webhook queues one enrichment per dossier it creates, so the analyst opens a dossier
        already half answered instead of waiting on each panel's first read. Cheap reads only -
        the expensive ones (sign-ins, BEC collection) stay lazy at first display:

        - the account's administrative status (Evidence.identity), resolving the user id from the
          UPN when the alert only named an address, and writing the resolved id back onto the
          entities so every later panel skips that lookup;
        - the audit-log download search for a type 20 dossier (Evidence.download), anchored on
          the dossier's own creation time;
        - the recent dossiers naming the same entity on the same tenant (Evidence.related): the
          scope question 'is this account a repeat customer' answered before it is asked.

        Runs from Receive-CippQueueTrigger, which swallows exceptions: every step therefore
        catches and logs for itself, one failed read never costs the others, and the whole run is
        idempotent - re-queuing the same dossier re-files the same keys.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,

        [Parameter(Mandatory = $true)]
        [string]$CaseId
    )

    $Case = @(Get-PSITSocCase -TenantFilter $TenantFilter -CaseId $CaseId) | Select-Object -First 1
    if (-not $Case) {
        Write-LogMessage -API 'PSITCaseEnrichment' -tenant $TenantFilter -message "Enrichment skipped: case $CaseId was not found." -sev Warn
        return
    }

    $Filed = [System.Collections.Generic.List[string]]::new()

    # --- identity: who the account is, and whether it is privileged -----------------------------
    try {
        $Upn = [string]$Case.Entities.upn
        $UserId = [string]$Case.Entities.userId
        if ($Upn -and -not $UserId) {
            $User = New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/users/$([uri]::EscapeDataString($Upn))?`$select=id" -tenantid $TenantFilter
            $UserId = [string]$User.id
            if ($UserId) {
                # Entities are replaced whole on write: carry the existing ones forward.
                $Entities = @{}
                foreach ($Property in ([pscustomobject]$Case.Entities).PSObject.Properties) { $Entities[$Property.Name] = $Property.Value }
                $Entities['userId'] = $UserId
                $null = Set-PSITSocCase -TenantFilter $TenantFilter -CaseId $CaseId -Analyst 'enrichment' -Entities $Entities
            }
        }
        if ($UserId -and $null -eq $Case.Evidence.identity) {
            $Status = Get-PSITUserAdminStatus -TenantFilter $TenantFilter -UserId $UserId
            if ($Status.ActiveRead) {
                $null = Set-PSITSocCase -TenantFilter $TenantFilter -CaseId $CaseId -Analyst 'enrichment' -Evidence @{
                    identity = [pscustomobject]@{
                        userId        = [string]$Status.UserId
                        isAdmin       = [bool]$Status.IsAdmin
                        isEligible    = [bool]$Status.IsEligible
                        activeRoles   = @($Status.ActiveRoles)
                        eligibleRoles = @($Status.EligibleRoles)
                        readUtc       = [string]$Status.ReadUtc
                    }
                }
                $Filed.Add('statut admin')
            }
        }
    } catch {
        Write-LogMessage -API 'PSITCaseEnrichment' -tenant $TenantFilter -message "Enrichment of case $($CaseId): identity read failed: $($_.Exception.Message)" -sev Warn
    }

    # --- type 20: the audit search the panel would otherwise launch at first open ---------------
    try {
        $Upn = [string]$Case.Entities.upn
        if ([int]$Case.TypeId -eq 20 -and $Upn -and [string]::IsNullOrWhiteSpace([string]$Case.Evidence.download.searchId)) {
            $null = Start-PSITDownloadAudit -TenantFilter $TenantFilter -UserPrincipalName $Upn -CaseId $CaseId -Analyst 'enrichment' -AroundUtc ([string]$Case.CreatedUtc)
            $Filed.Add("recherche d'audit des téléchargements")
        }
    } catch {
        Write-LogMessage -API 'PSITCaseEnrichment' -tenant $TenantFilter -message "Enrichment of case $($CaseId): download audit could not start: $($_.Exception.Message)" -sev Warn
    }

    # --- scope: recent dossiers naming the same entity -------------------------------------------
    try {
        $Keys = @('upn', 'userId', 'deviceName', 'deviceId', 'appId', 'networkMessageId')
        $Values = @{}
        foreach ($Key in $Keys) {
            $Value = [string]$Case.Entities.$Key
            if ($Value) { $Values[$Key] = $Value }
        }
        if ($Values.Count -gt 0) {
            $Related = @(Get-PSITSocCase -TenantFilter $TenantFilter) | Where-Object {
                if ($_.CaseId -eq $CaseId) { return $false }
                foreach ($Key in $Values.Keys) {
                    if ([string]$_.Entities.$Key -eq [string]$Values[$Key]) { return $true }
                }
                return $false
            }
            $Rows = @($Related | Sort-Object -Property CreatedUtc -Descending | Select-Object -First 5 | ForEach-Object {
                    [pscustomobject]@{
                        caseId     = $_.CaseId
                        title      = $_.Title
                        status     = $_.Status
                        verdict    = [string]$_.Qualification.Verdict
                        createdUtc = $_.CreatedUtc
                    }
                })
            $null = Set-PSITSocCase -TenantFilter $TenantFilter -CaseId $CaseId -Analyst 'enrichment' -Evidence @{
                related = [pscustomobject]@{
                    cases   = @($Rows)
                    readUtc = (Get-Date).ToUniversalTime().ToString('o')
                }
            }
            $Filed.Add("$(@($Rows).Count) dossier(s) lié(s)")
        }
    } catch {
        Write-LogMessage -API 'PSITCaseEnrichment' -tenant $TenantFilter -message "Enrichment of case $($CaseId): related-case scan failed: $($_.Exception.Message)" -sev Warn
    }

    if ($Filed.Count -gt 0) {
        $null = Set-PSITSocCase -TenantFilter $TenantFilter -CaseId $CaseId -Analyst 'enrichment' -LogAction @{
            Action = 'enriched'
            Detail = "Pré-rempli à l'ingestion : $($Filed -join ', ')."
        }
    }
    Write-LogMessage -API 'PSITCaseEnrichment' -tenant $TenantFilter -message "Enrichment of case $CaseId completed: $($Filed -join ', ')" -sev Info
}
