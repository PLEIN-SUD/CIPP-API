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

function Set-PSITSocWebhookSecret {
    <#
    .SYNOPSIS
        Generates a new shared secret for the SOC ingestion webhook, replacing any previous one.

    .DESCRIPTION
        Rotation is destructive by design: the old secret stops working the moment this returns,
        which is what makes it a rotation rather than a second key nobody can revoke. The caller
        is told to update the automation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Analyst
    )

    $Table = Get-CippTable -tablename 'PSITSocWebhook'
    $Now = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    # Two GUIDs: long enough that guessing is not a threat model, short enough to paste in a URL.
    $Secret = '{0}{1}' -f [guid]::NewGuid().ToString('N'), [guid]::NewGuid().ToString('N')

    $Entity = @{
        PartitionKey = 'Config'
        RowKey       = 'Secret'
        Secret       = $Secret
        RotatedUtc   = $Now
        RotatedBy    = $Analyst
    }
    $null = Add-CIPPAzDataTableEntity @Table -Entity $Entity -Force

    Write-LogMessage -API 'PSITSocWebhook' -tenant 'CIPP' -message "SOC ingestion webhook secret rotated by $Analyst" -sev Warn

    return [pscustomobject]@{
        Secret     = $Secret
        RotatedUtc = $Now
        RotatedBy  = $Analyst
    }
}
