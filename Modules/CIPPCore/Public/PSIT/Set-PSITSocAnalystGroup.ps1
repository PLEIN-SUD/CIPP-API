function Set-PSITSocAnalystGroup {
    <#
    .SYNOPSIS
        Records which Entra group holds this portal's SOC analysts, or clears it.

    .DESCRIPTION
        An empty GroupId clears the setting, which returns the analyst list to the portal's own
        roster. Clearing is a real gesture, not a mistake, so it is stored and logged like any
        other.

        The group's display name is resolved and stored beside its id, for one reason: an object
        id on a settings screen tells nobody whether it is the right group. It is a copy for
        display, refreshed on every save, never the thing that is matched against.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$GroupId,

        [Parameter(Mandatory)]
        [string]$Analyst
    )

    $Table = Get-CippTable -tablename 'PSITSocConfig'
    $Now = (Get-Date).ToUniversalTime().ToString('o')
    $Trimmed = $GroupId.Trim()

    if ([string]::IsNullOrWhiteSpace($Trimmed)) {
        $Entity = @{
            PartitionKey = 'Config'
            RowKey       = 'AnalystGroup'
            GroupId      = ''
            GroupName    = ''
            SetUtc       = $Now
            SetBy        = $Analyst
        }
        Add-CIPPAzDataTableEntity @Table -Entity $Entity -Force | Out-Null
        Write-LogMessage -API 'PSITSocAnalystGroup' -tenant 'CIPP' -message "SOC analyst group cleared by $Analyst." -sev Info
        return $null
    }

    # Resolved before it is stored: a group that cannot be read is a group that will produce an
    # empty analyst list, and finding that out on the settings screen beats finding it out from a
    # picker that offers nobody.
    $GroupName = ''
    try {
        $Group = New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/groups/$Trimmed`?`$select=id,displayName" -tenantid $env:TenantID -NoAuthCheck $true -AsApp $true
        $GroupName = [string]$Group.displayName
    } catch {
        throw "No group with id '$Trimmed' could be read from the partner tenant: $($_.Exception.Message)"
    }

    $Entity = @{
        PartitionKey = 'Config'
        RowKey       = 'AnalystGroup'
        GroupId      = $Trimmed
        GroupName    = $GroupName
        SetUtc       = $Now
        SetBy        = $Analyst
    }
    Add-CIPPAzDataTableEntity @Table -Entity $Entity -Force | Out-Null
    Write-LogMessage -API 'PSITSocAnalystGroup' -tenant 'CIPP' -message "SOC analyst group set to '$GroupName' by $Analyst." -sev Info

    return [pscustomobject]@{
        GroupId   = $Trimmed
        GroupName = $GroupName
        SetUtc    = $Now
        SetBy     = $Analyst
    }
}
