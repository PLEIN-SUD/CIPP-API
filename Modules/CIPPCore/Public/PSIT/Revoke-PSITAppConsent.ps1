function Revoke-PSITAppConsent {
    <#
    .SYNOPSIS
        Cuts the access an OAuth consent gave to an application, without deleting the application.

    .DESCRIPTION
        The containment gesture of a malicious or unexplained consent (SOC triage type 6), in
        three steps, each reported individually:

        1. Disable the service principal (accountEnabled=false): no token gets issued any more,
           whatever grants remain.
        2. Delete the oauth2PermissionGrants whose clientId is the service principal: the
           delegated consents, which is what a consent-phishing grant is.
        3. Delete the appRoleAssignments of the service principal: the application permissions,
           the persistence a password reset never touches.

        Deliberately NOT a deletion of the service principal: deleting destroys the evidence
        (grant dates, scopes) an investigation still needs, and a disabled principal can be
        re-enabled if the analyst got it wrong. Full removal stays with ExecApplication (Delete).

        A step that fails does not stop the following ones: a partially revoked consent is better
        than an untouched one, and the result says exactly what was done and what was not.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,

        # Object id of the service principal, or its appId: whichever the case carries.
        [string]$ServicePrincipalId,
        [string]$AppId,

        [Parameter(Mandatory = $true)]
        [string]$Analyst
    )

    if ([string]::IsNullOrWhiteSpace($ServicePrincipalId) -and [string]::IsNullOrWhiteSpace($AppId)) {
        throw 'Either ServicePrincipalId or AppId is required.'
    }

    $Results = [System.Collections.Generic.List[object]]::new()
    $Report = {
        param($Text, $State)
        $Results.Add([pscustomobject]@{ resultText = $Text; state = $State })
    }

    # Resolve to the service principal object, whichever identifier was given: every later call
    # needs the object id, and the display name makes the log readable.
    $ServicePrincipal = if (-not [string]::IsNullOrWhiteSpace($ServicePrincipalId)) {
        New-GraphGetRequest -uri "https://graph.microsoft.com/beta/servicePrincipals/$($ServicePrincipalId)?`$select=id,appId,displayName,accountEnabled" -tenantid $TenantFilter
    } else {
        New-GraphGetRequest -uri "https://graph.microsoft.com/beta/servicePrincipals?`$filter=appId eq '$AppId'&`$select=id,appId,displayName,accountEnabled" -tenantid $TenantFilter | Select-Object -First 1
    }
    if (-not $ServicePrincipal.id) {
        throw "No service principal found for '$($ServicePrincipalId ?? $AppId)' on $TenantFilter."
    }
    $SpId = $ServicePrincipal.id
    $Name = $ServicePrincipal.displayName ?? $ServicePrincipal.appId

    # Step 1: disable. First, because it closes the door while the grants are being swept.
    try {
        $null = New-GraphPOSTRequest -uri "https://graph.microsoft.com/beta/servicePrincipals/$SpId" -type PATCH -tenantid $TenantFilter -body (@{ accountEnabled = $false } | ConvertTo-Json -Compress)
        & $Report "Disabled service principal $Name" 'success'
    } catch {
        & $Report "Failed to disable service principal ${Name}: $($_.Exception.Message)" 'error'
    }

    # Step 2: delegated grants.
    $Removed = [System.Collections.Generic.List[object]]::new()
    try {
        $Grants = @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/oauth2PermissionGrants?`$filter=clientId eq '$SpId'" -tenantid $TenantFilter)
        foreach ($Grant in $Grants) {
            if (-not $Grant.id) { continue }
            # Kept before it is deleted. These grants are the evidence that justified the
            # revocation, and a report written afterwards read a tenant where they no longer
            # exist: it showed an application with no consent and no permission, which is the
            # state the revocation created, not the state that was investigated.
            $Removed.Add([pscustomobject]@{
                    consentType = [string]$Grant.consentType
                    principalId = [string]$Grant.principalId
                    scope       = [string]$Grant.scope
                })
            $null = New-GraphPOSTRequest -uri "https://graph.microsoft.com/beta/oauth2PermissionGrants/$($Grant.id)" -type DELETE -tenantid $TenantFilter -body ''
        }
        & $Report "Removed $(@($Grants | Where-Object { $_.id }).Count) delegated grant(s) of $Name" 'success'
    } catch {
        & $Report "Failed to remove the delegated grants of ${Name}: $($_.Exception.Message)" 'error'
    }

    # Step 3: application role assignments.
    try {
        $Assignments = @(New-GraphGetRequest -uri "https://graph.microsoft.com/beta/servicePrincipals/$SpId/appRoleAssignments" -tenantid $TenantFilter)
        foreach ($Assignment in $Assignments) {
            if (-not $Assignment.id) { continue }
            $null = New-GraphPOSTRequest -uri "https://graph.microsoft.com/beta/servicePrincipals/$SpId/appRoleAssignments/$($Assignment.id)" -type DELETE -tenantid $TenantFilter -body ''
        }
        & $Report "Removed $(@($Assignments | Where-Object { $_.id }).Count) application role assignment(s) of $Name" 'success'
    } catch {
        & $Report "Failed to remove the application role assignments of ${Name}: $($_.Exception.Message)" 'error'
    }

    Write-LogMessage -API 'PSITExecRevokeAppConsent' -tenant $TenantFilter -message "App consent revocation on $Name ($SpId) by $Analyst" -sev Info

    return [pscustomobject]@{
        ServicePrincipalId = $SpId
        AppId              = [string]$ServicePrincipal.appId
        DisplayName        = [string]$Name
        PublisherName      = [string]$ServicePrincipal.publisherName
        CreatedDateTime    = [string]$ServicePrincipal.createdDateTime
        RemovedGrants      = @($Removed)
        RevokedUtc         = (Get-Date).ToUniversalTime().ToString('o')
        Results            = @($Results)
    }
}
