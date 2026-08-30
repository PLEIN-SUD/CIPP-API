function Get-PSITUserAdminStatus {
    <#
    .SYNOPSIS
        Says whether an account holds administrative power in its tenant, and how.

    .DESCRIPTION
        Two readings, because a badge that counts only permanent roles calls an account standard
        while it can make itself Global Administrator in thirty seconds.

        Active roles come from transitiveMemberOf, which answers with the roles the account holds
        right now - including those it holds through a group, which a read of direct assignments
        would miss entirely.

        Eligible roles come from PIM. A tenant without the licence answers with an error, and that
        is not an outage: the reading degrades to 'active only' and says so, rather than reporting
        an account as non-admin because half the question could not be asked.

        The roles themselves are returned so a screen can list them on demand, but the badge is
        one fact - administrator, or eligible to become one - because roles accumulate and a cell
        printing four of them says less than one saying what they amount to.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TenantFilter,

        [Parameter(Mandatory)]
        [string]$UserId
    )

    $Warnings = [System.Collections.Generic.List[string]]::new()
    $Active = [System.Collections.Generic.List[string]]::new()
    $Eligible = [System.Collections.Generic.List[string]]::new()
    $ActiveRead = $false
    $EligibleRead = $false

    try {
        $Roles = @(New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/users/$UserId/transitiveMemberOf/microsoft.graph.directoryRole?`$select=id,displayName,roleTemplateId" -tenantid $TenantFilter)
        foreach ($Role in @($Roles | Where-Object { $_.displayName })) {
            if (-not $Active.Contains([string]$Role.displayName)) { $Active.Add([string]$Role.displayName) }
        }
        $ActiveRead = $true
    } catch {
        $Warnings.Add("Rôles actifs illisibles ($($_.Exception.Message)). Le badge ne peut pas être affirmé.")
    }

    try {
        $Schedules = @(New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$filter=principalId eq '$UserId'&`$expand=roleDefinition(`$select=displayName)" -tenantid $TenantFilter)
        foreach ($Schedule in @($Schedules | Where-Object { $_.roleDefinition.displayName })) {
            $Name = [string]$Schedule.roleDefinition.displayName
            if (-not $Eligible.Contains($Name)) { $Eligible.Add($Name) }
        }
        $EligibleRead = $true
    } catch {
        # A tenant without Entra ID P2 has no PIM at all, which is an answer and not a failure.
        $Warnings.Add("Éligibilités PIM non lues ($($_.Exception.Message)). Un rôle activable à la demande ne serait pas signalé.")
    }

    [pscustomobject]@{
        UserId        = $UserId
        IsAdmin       = $Active.Count -gt 0
        IsEligible    = $Eligible.Count -gt 0
        ActiveRoles   = @($Active)
        EligibleRoles = @($Eligible)
        # Stated rather than implied: a screen must be able to tell 'not an administrator' from
        # 'we could not find out', and those look identical in the fields above.
        ActiveRead    = $ActiveRead
        EligibleRead  = $EligibleRead
        ReadUtc       = (Get-Date).ToUniversalTime().ToString('o')
        Warnings      = @($Warnings)
    }
}
