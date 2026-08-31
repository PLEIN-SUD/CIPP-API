Function Invoke-PSITExecSocEscalate {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Security.Incident.ReadWrite
    .DESCRIPTION
        Escalates a dossier to a named analyst: reassignment, a journal entry carrying the
        mandatory reason, and a direct mail to the recipient with the dossier link.

        The mail goes through Send-CIPPAlert with -altEmail, which bypasses the notification
        configuration on purpose: an escalation must reach its recipient whether or not the
        portal's general notifications are set up. And a failed mail never fails the
        escalation - the reassignment and the journal entry are the escalation; the mail is how
        the recipient learns of it, and the response says when they did not.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $TenantFilter = Get-PSITSocRequestValue -Value ($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
    $CaseId = Get-PSITSocRequestValue -Value ($Request.Query.CaseId ?? $Request.Body.CaseId)
    $EscalateTo = Get-PSITSocRequestValue -Value ($Request.Body.EscalateTo)
    $Reason = Get-PSITSocRequestValue -Value ($Request.Body.Reason)

    if ([string]::IsNullOrWhiteSpace($TenantFilter) -or [string]::IsNullOrWhiteSpace($CaseId)) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'tenantFilter and CaseId are both required.' }
            })
    }
    if ([string]::IsNullOrWhiteSpace($EscalateTo) -or [string]::IsNullOrWhiteSpace($Reason)) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = "Une escalade nomme son destinataire et dit pourquoi : les deux champs sont obligatoires." }
            })
    }

    try {
        $Analyst = Get-PSITBecAnalyst -Headers $Request.Headers

        $Case = Set-PSITSocCase -TenantFilter $TenantFilter -CaseId $CaseId -Analyst $Analyst -AssignedTo $EscalateTo -LogAction @{
            Action = 'escalated'
            Detail = "Escaladé à $EscalateTo par $Analyst : $Reason"
        }

        $Warnings = [System.Collections.Generic.List[string]]::new()
        try {
            # The dossier link, from the portal's own recorded URL.
            $CippConfigTable = Get-CippTable -tablename Config
            $CippConfig = Get-CIPPAzDataTableEntity @CippConfigTable -Filter "PartitionKey eq 'InstanceProperties' and RowKey eq 'CIPPURL'"
            $CaseUrl = if ($CippConfig.Value) {
                'https://{0}/security/soc/case?caseId={1}&tenantFilter={2}' -f $CippConfig.Value, $CaseId, [uri]::EscapeDataString($TenantFilter)
            } else { '' }

            $Html = @"
<p>$Analyst vous escalade le dossier <strong>$($Case.Title)</strong> ($CaseId, client $TenantFilter).</p>
<p><strong>Motif :</strong> $Reason</p>
$(if ($CaseUrl) { "<p><a href=`"$CaseUrl`">Ouvrir le dossier</a></p>" })
"@
            $null = Send-CIPPAlert -Type 'email' -Title "Escalade SOC : $($Case.Title) ($CaseId)" -HTMLContent $Html -altEmail $EscalateTo -TenantFilter $TenantFilter -APIName $APIName
        } catch {
            $Warnings.Add("Le dossier est réattribué et l'escalade journalisée, mais le mail vers $EscalateTo n'est pas parti ($($_.Exception.Message)) : prévenez-le autrement.")
            Write-LogMessage -headers $Request.Headers -API $APIName -tenant $TenantFilter -message "Escalation mail to $EscalateTo failed for case $($CaseId): $($_.Exception.Message)" -sev Warn
        }

        Write-LogMessage -headers $Request.Headers -API $APIName -tenant $TenantFilter -message "Case $CaseId escalated to $EscalateTo by $Analyst" -sev Info
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @{
                    Results  = "Dossier escaladé à $EscalateTo."
                    Warnings = @($Warnings)
                }
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API $APIName -tenant $TenantFilter -message "Could not escalate case $($CaseId): $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = "L'escalade n'a pas abouti : $($ErrorMessage.NormalizedError)" }
            })
    }
}
