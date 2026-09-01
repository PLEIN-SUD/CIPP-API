function Get-PSITIpReputation {
    <#
    .SYNOPSIS
        The AbuseIPDB reputation of a set of addresses, through a 24-hour cache.

    .DESCRIPTION
        Answers for the chips next to every address on the SOC screens: abuse confidence score,
        report count, country, ISP, usage type, Tor. Three rules shape it:

        - the cache comes first (PSITIpReputation table, 24 h): reputation moves slowly, the free
          quota is a thousand checks a day, and a dossier re-opened all afternoon must not spend
          it. The cached row carries CheckedUtc, so what is shown is always dated;
        - private and invalid addresses are never sent out: 10/8, 172.16/12, 192.168/16, 127/8,
          169.254/16 and their IPv6 siblings answer nothing rather than leak internal topology
          to a third party;
        - a lookup failure degrades to the stale cached row when one exists (dated), and to
          nothing otherwise - never to a fabricated zero.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [string[]]$Ips = @(),

        [int]$CacheHours = 24
    )

    $Notes = [System.Collections.Generic.List[string]]::new()

    $IsPrivate = {
        param([string]$Ip)
        if ($Ip -match '^(10\.|127\.|192\.168\.|169\.254\.)') { return $true }
        if ($Ip -match '^172\.(1[6-9]|2\d|3[01])\.') { return $true }
        if ($Ip -match '^(fe80:|fc|fd|::1$)') { return $true }
        return $false
    }

    $Wanted = [System.Collections.Generic.List[string]]::new()
    foreach ($Ip in @($Ips | Where-Object { $_ } | Select-Object -Unique | Select-Object -First 20)) {
        $Candidate = $Ip.Trim()
        $Parsed = $null
        if (-not [System.Net.IPAddress]::TryParse($Candidate, [ref]$Parsed)) { continue }
        if (& $IsPrivate $Candidate) { continue }
        $Wanted.Add($Candidate)
    }
    if ($Wanted.Count -eq 0) {
        return [pscustomobject]@{ Rows = @(); Notes = @($Notes) }
    }

    $KeyRow = Get-PSITIpReputationKey
    $Table = Get-CippTable -tablename 'PSITIpReputation'
    $Cutoff = (Get-Date).ToUniversalTime().AddHours(-1 * [Math]::Abs($CacheHours))

    $Rows = [System.Collections.Generic.List[object]]::new()
    foreach ($Ip in $Wanted) {
        $Cached = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'IP' and RowKey eq '$Ip'"
        $CachedFresh = $false
        if ($Cached.CheckedUtc) {
            try {
                $CachedFresh = [datetime]::Parse([string]$Cached.CheckedUtc, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal) -ge $Cutoff
            } catch {
                $CachedFresh = $false
            }
        }

        if (-not $CachedFresh -and $KeyRow) {
            try {
                $Answer = Invoke-RestMethod -Method GET -Uri "https://api.abuseipdb.com/api/v2/check?ipAddress=$([uri]::EscapeDataString($Ip))&maxAgeInDays=90" -Headers @{
                    Key    = $KeyRow.Key
                    Accept = 'application/json'
                }
                $Data = $Answer.data
                $Entity = @{
                    PartitionKey = 'IP'
                    RowKey       = $Ip
                    Score        = [string]([int]$Data.abuseConfidenceScore)
                    Reports      = [string]([int]$Data.totalReports)
                    Country      = [string]$Data.countryCode
                    Isp          = [string]$Data.isp
                    UsageType    = [string]$Data.usageType
                    IsTor        = [string]([bool]$Data.isTor)
                    Domain       = [string]$Data.domain
                    CheckedUtc   = (Get-Date).ToUniversalTime().ToString('o')
                }
                Add-CIPPAzDataTableEntity @Table -Entity $Entity -Force | Out-Null
                $Cached = [pscustomobject]$Entity
                $CachedFresh = $true
            } catch {
                Write-LogMessage -API 'PSITIpReputation' -tenant 'CIPP' -message "AbuseIPDB lookup failed for one address: $($_.Exception.Message)" -sev Warn
                $Notes.Add("Consultation AbuseIPDB en échec pour $Ip : affichage du dernier relevé connu, s'il existe.")
            }
        }

        if ($Cached.CheckedUtc) {
            $Rows.Add([pscustomobject]@{
                    Ip         = $Ip
                    Score      = [int]$Cached.Score
                    Reports    = [int]$Cached.Reports
                    Country    = [string]$Cached.Country
                    Isp        = [string]$Cached.Isp
                    UsageType  = [string]$Cached.UsageType
                    IsTor      = ([string]$Cached.IsTor -eq 'True')
                    CheckedUtc = [string]$Cached.CheckedUtc
                    Stale      = -not $CachedFresh
                })
        }
    }

    if (-not $KeyRow) {
        $Notes.Add("Aucune clé AbuseIPDB configurée : seule la mémoire locale répond. Réglage sur l’écran Ingestion.")
    }

    [pscustomobject]@{ Rows = @($Rows); Notes = @($Notes) }
}
