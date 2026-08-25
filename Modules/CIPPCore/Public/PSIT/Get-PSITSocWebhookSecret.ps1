function Get-PSITSocWebhookSecret {
    <#
    .SYNOPSIS
        Reads the shared secret that authorises the SOC ingestion webhook.

    .DESCRIPTION
        Returns null when no secret has been generated. The webhook fails closed on that: an
        unauthenticated endpoint that creates records is not something to enable by accident, so
        the absence of a secret means the door is shut, never that it is open.
    #>
    [CmdletBinding()]
    param()

    $Table = Get-CippTable -tablename 'PSITSocWebhook'
    $Row = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'Config' and RowKey eq 'Secret'"
    if (-not $Row.Secret) { return $null }

    return [pscustomobject]@{
        Secret     = [string]$Row.Secret
        RotatedUtc = [string]$Row.RotatedUtc
        RotatedBy  = [string]$Row.RotatedBy
    }
}

