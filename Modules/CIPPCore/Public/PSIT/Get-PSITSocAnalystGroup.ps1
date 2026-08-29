function Get-PSITSocAnalystGroup {
    <#
    .SYNOPSIS
        Reads the Entra group whose members are this portal's SOC analysts.

    .DESCRIPTION
        Returns null when none is configured, which is not an error: without one, the analyst list
        falls back to the portal's own roster and then to the partner tenant's accounts.

        The group lives in configuration rather than in code on purpose. Its object id and its name
        are production facts about one tenant, and these repositories are public.
    #>
    [CmdletBinding()]
    param()

    $Table = Get-CippTable -tablename 'PSITSocConfig'
    $Row = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Config' and RowKey eq 'AnalystGroup'"
    if ([string]::IsNullOrWhiteSpace($Row.GroupId)) { return $null }

    return [pscustomobject]@{
        GroupId   = [string]$Row.GroupId
        GroupName = [string]$Row.GroupName
        SetUtc    = [string]$Row.SetUtc
        SetBy     = [string]$Row.SetBy
    }
}
