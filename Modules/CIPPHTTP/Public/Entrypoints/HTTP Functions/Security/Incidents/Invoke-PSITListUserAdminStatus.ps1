Function Invoke-PSITListUserAdminStatus {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Identity.User.Read
    .DESCRIPTION
        Says whether an account holds administrative power in its tenant: a badge, plus the roles
        behind it for a screen that wants to list them.

        Given a CaseId, the answer is also filed on the dossier. That is the point of asking in a
        dossier: an account's roles can be removed - by the remediation itself, or by an
        administrator the next morning - and a report written afterwards would then describe a
        standard user. The dossier keeps what was true when it was investigated.

        Filing never fails the read: an answer the caller can display beats a refusal because the
        record could not be updated.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = Get-PSITSocRequestValue -Value ($Request.Query.tenantFilter ?? $Request.Body.tenantFilter)
    $UserId = Get-PSITSocRequestValue -Value ($Request.Query.UserId ?? $Request.Body.UserId)
    $CaseId = Get-PSITSocRequestValue -Value ($Request.Query.CaseId ?? $Request.Body.CaseId)

    if ([string]::IsNullOrWhiteSpace($TenantFilter) -or [string]::IsNullOrWhiteSpace($UserId)) {
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ Results = 'tenantFilter and UserId are both required.' }
            })
    }

    try {
        $Status = Get-PSITUserAdminStatus -TenantFilter $TenantFilter -UserId $UserId

        if (-not [string]::IsNullOrWhiteSpace($CaseId) -and $Status.ActiveRead) {
            try {
                $Analyst = Get-PSITBecAnalyst -Headers $Request.Headers
                $null = Set-PSITSocCase -TenantFilter $TenantFilter -CaseId $CaseId -Analyst $Analyst -Evidence @{
                    identity = [pscustomobject]@{
                        userId        = [string]$Status.UserId
                        isAdmin       = [bool]$Status.IsAdmin
                        isEligible    = [bool]$Status.IsEligible
                        activeRoles   = @($Status.ActiveRoles)
                        eligibleRoles = @($Status.EligibleRoles)
                        readUtc       = [string]$Status.ReadUtc
                    }
                }
            } catch {
                Write-LogMessage -headers $Request.Headers -API 'PSITListUserAdminStatus' -tenant $TenantFilter -message "Admin status read but could not be filed on case $($CaseId): $($_.Exception.Message)" -sev Warn
            }
        }

        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::OK
                Body       = $Status
            })
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        Write-LogMessage -headers $Request.Headers -API 'PSITListUserAdminStatus' -tenant $TenantFilter -message "Could not read the administrative status of $($UserId): $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Body       = @{ Results = "Could not read the administrative status: $($ErrorMessage.NormalizedError)" }
            })
    }
}
