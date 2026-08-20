function Get-PSITBecTriage {
    <#
    .SYNOPSIS
        Reads the analyst determinations recorded for a mailbox.

    .DESCRIPTION
        Returns an empty determination set rather than nothing when no triage exists, so callers
        can render "nothing qualified yet" without special-casing a null.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,

        [Parameter(Mandatory = $true)]
        [string]$UserId
    )

    $Table = Get-CippTable -tablename 'PSITBecTriage'
    $Row = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq '$TenantFilter' and RowKey eq '$UserId'"

    $Determinations = @()
    if ($Row.Determinations) {
        try {
            $Determinations = @($Row.Determinations | ConvertFrom-Json -ErrorAction Stop)
        } catch {
            Write-Information "Triage for $UserId could not be parsed: $($_.Exception.Message)"
            $Determinations = @()
        }
    }

    return [pscustomobject]@{
        TenantFilter      = $TenantFilter
        UserId            = $UserId
        UserPrincipalName = [string]$Row.UserPrincipalName
        Determinations    = $Determinations
        UpdatedBy         = [string]$Row.UpdatedBy
        UpdatedUtc        = [string]$Row.UpdatedUtc
    }
}
