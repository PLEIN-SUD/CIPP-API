function Test-PSITBecServiceIp {
    <#
    .SYNOPSIS
        Tells whether an address belongs to Microsoft's own mail infrastructure.

    .DESCRIPTION
        Message trace records the address that submitted the message, which for anything the
        service generates itself - automatic replies, non-delivery reports, journaling - is an
        Exchange Online address, not the user's. Those addresses geolocate wherever Microsoft
        registered the range, so a French mailbox produces "sent from Canada" for every automatic
        reply.

        In one real investigation that turned 166 of 177 outbound messages into "activity outside
        the user's country", which is what made the whole report read as noise. So the check
        exists to keep service traffic out of any location comparison.

        Two mechanisms, in order:
          1. The autonomous system name from the geo lookup (Get-CIPPGeoIPLocationBatch returns
             ASName). This is the reliable one: it follows Microsoft's ranges as they change.
          2. A prefix list, used when the geo lookup failed or returned Unknown - the documented
             Exchange Online Protection ranges. Bit-exact CIDR matching, not string matching, so
             2603:10a6:: matches 2603:1000::/24 while 2603:2000:: does not.

    .PARAMETER Ip
        The address as recorded by message trace. Port and brackets are tolerated.

    .PARAMETER GeoInfo
        Optional record from Get-CIPPGeoIPLocationBatch for this address (ASName is read).
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Ip,

        [AllowNull()]
        $GeoInfo
    )

    if ([string]::IsNullOrWhiteSpace($Ip)) { return $false }

    # Autonomous system name first: it tracks Microsoft's ranges without a hardcoded list.
    $AsName = [string]$GeoInfo.ASName
    if ($AsName -and $AsName -ne 'Unknown') {
        if ($AsName -match '(?i)microsoft|MSFT|MSN-AS-BLOCK|Exchange Online') { return $true }
    }

    $Clean = (($Ip -replace '[\[\]]', '') -split '%')[0].Trim()
    # Strip a trailing :port on IPv4 only - a bare IPv6 address is full of colons.
    if ($Clean -match '^(\d{1,3}(\.\d{1,3}){3}):\d+$') { $Clean = $Matches[1] }

    $Address = $null
    if (-not [System.Net.IPAddress]::TryParse($Clean, [ref]$Address)) { return $false }

    # Documented Exchange Online Protection / Microsoft ranges. Kept short on purpose: this is
    # the fallback for a failed geo lookup, not an attempt to enumerate Microsoft's network.
    $Prefixes = @(
        '2603:1000::/24'    # Microsoft, carries the 2603:10a6:: EOP addresses
        '2a01:111::/32'     # Microsoft Europe, EOP and Office 365
        '2620:1ec::/36'     # Microsoft
        '40.92.0.0/15'      # EOP outbound
        '40.107.0.0/16'     # EOP outbound
        '52.100.0.0/14'     # EOP outbound
        '104.47.0.0/17'     # EOP outbound
    )

    $AddressBytes = $Address.GetAddressBytes()
    foreach ($Prefix in $Prefixes) {
        $Parts = $Prefix -split '/'
        $Network = $null
        if (-not [System.Net.IPAddress]::TryParse($Parts[0], [ref]$Network)) { continue }
        if ($Network.AddressFamily -ne $Address.AddressFamily) { continue }

        $NetworkBytes = $Network.GetAddressBytes()
        $Bits = [int]$Parts[1]
        $FullBytes = [Math]::Floor($Bits / 8)
        $RemainingBits = $Bits % 8

        $Match = $true
        for ($i = 0; $i -lt $FullBytes; $i++) {
            if ($AddressBytes[$i] -ne $NetworkBytes[$i]) { $Match = $false; break }
        }
        if ($Match -and $RemainingBits -gt 0) {
            # -band 0xFF before the cast: a left shift widens past 8 bits (0xFF -shl 1 is 510),
            # which [byte] refuses rather than truncating.
            $Mask = [byte](((0xFF -shl (8 - $RemainingBits))) -band 0xFF)
            if (($AddressBytes[$FullBytes] -band $Mask) -ne ($NetworkBytes[$FullBytes] -band $Mask)) { $Match = $false }
        }
        if ($Match) { return $true }
    }

    return $false
}
