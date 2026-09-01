function Get-PSITIpReputationKey {
    <#
    .SYNOPSIS
        Reads the AbuseIPDB API key from configuration.

    .DESCRIPTION
        Returns null when none is configured, which is not an error: without a key the reputation
        chips simply do not exist, and the settings screen says why. The key lives in
        configuration, never in code or in an answer to the frontend - these repositories are
        public, and a key is a credential.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param()

    $Table = Get-CippTable -tablename 'PSITSocConfig'
    $Row = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Config' and RowKey eq 'IpReputationKey'"
    if ([string]::IsNullOrWhiteSpace($Row.Key)) { return $null }

    return [pscustomobject]@{
        Key    = [string]$Row.Key
        SetUtc = [string]$Row.SetUtc
        SetBy  = [string]$Row.SetBy
    }
}
