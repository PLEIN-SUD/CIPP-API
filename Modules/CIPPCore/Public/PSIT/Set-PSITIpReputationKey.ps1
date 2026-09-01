function Set-PSITIpReputationKey {
    <#
    .SYNOPSIS
        Records the AbuseIPDB API key, or clears it.

    .DESCRIPTION
        The key is validated with one live check before it is stored: a mistyped key discovered
        on the settings screen beats one discovered as silently absent chips on every dossier.
        An empty key clears the setting, which removes the reputation chips everywhere - a real
        gesture, stored and logged like any other. The key itself is never logged and never
        returned.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Key,

        [Parameter(Mandatory)]
        [string]$Analyst
    )

    $Table = Get-CippTable -tablename 'PSITSocConfig'
    $Now = (Get-Date).ToUniversalTime().ToString('o')
    $Trimmed = $Key.Trim()

    if ([string]::IsNullOrWhiteSpace($Trimmed)) {
        $Entity = @{
            PartitionKey = 'Config'
            RowKey       = 'IpReputationKey'
            Key          = ''
            SetUtc       = $Now
            SetBy        = $Analyst
        }
        Add-CIPPAzDataTableEntity @Table -Entity $Entity -Force | Out-Null
        Write-LogMessage -API 'PSITIpReputation' -tenant 'CIPP' -message "AbuseIPDB key cleared by $Analyst." -sev Info
        return [pscustomobject]@{ Configured = $false }
    }

    # Validated before it is stored, against an address that always exists.
    try {
        $null = Invoke-RestMethod -Method GET -Uri 'https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=30' -Headers @{
            Key      = $Trimmed
            Accept   = 'application/json'
        }
    } catch {
        throw "La clé n'a pas été acceptée par AbuseIPDB : $($_.Exception.Message)"
    }

    $Entity = @{
        PartitionKey = 'Config'
        RowKey       = 'IpReputationKey'
        Key          = $Trimmed
        SetUtc       = $Now
        SetBy        = $Analyst
    }
    Add-CIPPAzDataTableEntity @Table -Entity $Entity -Force | Out-Null
    Write-LogMessage -API 'PSITIpReputation' -tenant 'CIPP' -message "AbuseIPDB key set by $Analyst (validated with one live check)." -sev Info
    return [pscustomobject]@{ Configured = $true; SetUtc = $Now }
}
