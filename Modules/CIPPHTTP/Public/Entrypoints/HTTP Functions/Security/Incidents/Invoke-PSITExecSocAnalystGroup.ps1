Function Invoke-PSITExecSocAnalystGroup {
    <#
    .FUNCTIONALITY
        Entrypoint,AnyTenant
    .ROLE
        Security.Incident.ReadWrite
    .DESCRIPTION
        Reads or sets the Entra group whose members are proposed when a SOC dossier is reassigned.
        An empty GroupId clears it, which returns the list to the portal's own users.

        AnyTenant for the same reason as the analyst list itself: the setting is about the people
        who use this portal, so there is no customer tenant to filter on, and without the
        declaration the access check falls back to the partner tenant and refuses every
        customer-scoped role.

        The group's id is never stored in the repository: it is a production fact about one
        tenant, and these repositories are public.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $Analyst = Get-PSITBecAnalyst -Headers $Request.Headers
    $GroupId = Get-PSITSocRequestValue -Value ($Request.Query.GroupId ?? $Request.Body.GroupId)
    $Setting = $null -ne $GroupId

    try {
        if ($Setting) {
            $Group = Set-PSITSocAnalystGroup -GroupId ([string]$GroupId) -Analyst $Analyst
        } else {
            $Group = Get-PSITSocAnalystGroup
        }

        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = @{
                    Results   = if (-not $Setting) {
                        if ($Group) { "Analysts are taken from '$($Group.GroupName)'." } else { "No analyst group is set: the portal's own users are proposed." }
                    } elseif ($Group) {
                        "Analysts are now taken from '$($Group.GroupName)'."
                    } else {
                        "Analyst group cleared: the portal's own users are proposed again."
                    }
                    GroupId   = [string]$Group.GroupId
                    GroupName = [string]$Group.GroupName
                    SetUtc    = [string]$Group.SetUtc
                    SetBy     = [string]$Group.SetBy
                }
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'PSITExecSocAnalystGroup' -tenant 'CIPP' -message "Could not set the SOC analyst group: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = $ErrorMessage.NormalizedError }
            })
    }
}
