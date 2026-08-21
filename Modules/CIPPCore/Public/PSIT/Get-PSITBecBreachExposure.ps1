function Test-PsitPngComplete {
    <#
    .SYNOPSIS
        Whether a byte array is a PNG that starts and finishes properly.

    .DESCRIPTION
        Signature at the front, IEND chunk at the back. That does not prove every pixel is intact,
        but it catches the realistic failure - a truncated download - and truncation is what makes
        react-pdf hang instead of raising. Cheap enough to run on every logo.
    #>
    [CmdletBinding()]
    param([byte[]]$Bytes)

    if ($null -eq $Bytes -or $Bytes.Length -lt 20) { return $false }

    $Signature = @(137, 80, 78, 71, 13, 10, 26, 10)
    for ($Index = 0; $Index -lt $Signature.Count; $Index++) {
        if ($Bytes[$Index] -ne $Signature[$Index]) { return $false }
    }

    # The last twelve bytes of a complete PNG are the IEND chunk: length 0, tag, CRC.
    $Tail = $Bytes[($Bytes.Length - 8)..($Bytes.Length - 5)]
    return ($Tail[0] -eq 73 -and $Tail[1] -eq 69 -and $Tail[2] -eq 78 -and $Tail[3] -eq 68)
}

function Get-PSITBecBreachExposure {
    <#
    .SYNOPSIS
        Public-breach exposure of the mailbox addresses, as a snapshot for the incident dossier.

    .DESCRIPTION
        Answers one question for the report: does this address appear in public credential dumps,
        and did any of them expose passwords. That is a risk factor for password reuse. It is NOT
        the initial access vector of the incident, and the report says so in as many words -
        conflating the two is how an incident report ends up asserting a cause it never established.

        Runs at COLLECTION time, never at render. The result is stored in the dossier with the time
        of the check and its source, so two generations of the same dossier produce the same report.
        A lookup at render time would make the document depend on when it was printed and on a third
        party being up.

        Nothing sensitive is stored. HIBP's breachedaccount endpoint returns no password and no
        fragment - that field only exists on the domain-wide proxy, which this never calls - but the
        normalisation is a WHITELIST of four fields rather than a blacklist, so a future change to
        the API cannot leak something new into the dossier. "Password exposed" is derived from the
        DataClasses list, not from a received value.

    .PARAMETER Addresses
        The mailbox addresses to look up: the UPN and its SMTP aliases. Deduplicated
        case-insensitively, capped, and the addresses actually queried are reported back - a report
        that cannot say what it looked at asserts a coverage nobody can reconstruct.

    .PARAMETER MaxAddresses
        How many addresses to query. Each one is a request against a quota, inside a function
        capped at ten minutes.

    .PARAMETER MaxLogoBytes
        A single logo above this is skipped. The dossier is one table entity and its JSON travels
        whole to the browser.

    .PARAMETER MaxLogoTotalBytes
        Total logo budget. Past it, the remaining breaches keep their data and lose their logo.

    .PARAMETER RequestCommand
        Injection point for the tests: defaults to Get-HIBPRequest.

    .PARAMETER LogoCommand
        Injection point for the tests: defaults to the logo fetch.

    .OUTPUTS
        A hashtable with Status, CheckedUtc, Source, Addresses, Breaches and the aggregates. Status
        is 'ok', 'not-configured', 'rate-limited' or 'error' - four states, because "no exposure"
        and "we could not look" must never render as the same sentence.
    #>
    [CmdletBinding()]
    param(
        # Empty and null members are allowed through validation on purpose: proxyAddresses carries
        # blanks and non-SMTP entries, and rejecting them at the parameter would make the caller
        # filter before it can know what this function considers usable.
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [AllowNull()]
        [string[]]$Addresses,

        [Parameter()]
        [int]$MaxAddresses = 4,

        [Parameter()]
        [int]$MaxLogoBytes = 12000,

        [Parameter()]
        [int]$MaxLogoTotalBytes = 60000,

        [Parameter()]
        [scriptblock]$RequestCommand,

        [Parameter()]
        [scriptblock]$LogoCommand
    )

    $Source = 'Have I Been Pwned (api/v3/breachedaccount)'
    $CheckedUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

    # Deduplicate on the lowercase form but keep the address as written: the report prints it.
    $Seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $Wanted = [System.Collections.Generic.List[string]]::new()
    foreach ($Address in $Addresses) {
        $Trimmed = [string]$Address
        $Trimmed = $Trimmed.Trim()
        if ([string]::IsNullOrWhiteSpace($Trimmed)) { continue }
        if ($Trimmed -notlike '*@*') { continue }
        if ($Seen.Add($Trimmed)) { $Wanted.Add($Trimmed) }
    }

    $Queried = @($Wanted | Select-Object -First $MaxAddresses)
    $Skipped = @($Wanted).Count - @($Queried).Count

    if (@($Queried).Count -eq 0) {
        return @{
            Status         = 'error'
            Reason         = 'aucune adresse exploitable'
            CheckedUtc     = $CheckedUtc
            Source         = $Source
            Addresses      = @()
            AddressesTotal = @($Wanted).Count
            Breaches       = @()
            BreachCount    = 0
            PasswordCount  = 0
            YearMin        = $null
            YearMax        = $null
        }
    }

    $Request = if ($RequestCommand) { $RequestCommand } else {
        { param($Endpoint) Get-HIBPRequest -endpoint $Endpoint }
    }
    $FetchLogo = if ($LogoCommand) { $LogoCommand } else {
        {
            param($Url)
            # Kept deliberately small and silent: a logo is decoration, and a decoration must never
            # be the reason a dossier fails to collect.
            $Response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
            [pscustomobject]@{
                Bytes       = $Response.Content
                ContentType = [string]$Response.Headers['Content-Type']
            }
        }
    }

    # Breaches keyed on Name: the same breach comes back for the UPN and for an alias, and the
    # report counts compromises, not lookups.
    $ByName = [ordered]@{}

    foreach ($Address in $Queried) {
        $Encoded = [System.Uri]::EscapeDataString($Address)
        try {
            $Raw = & $Request "breachedaccount/$Encoded`?truncateResponse=false"
        } catch {
            $Message = $_.Exception.Message
            # 401 is the shape of a missing or refused key, and it is worth telling apart from a
            # network failure: one is a configuration to fix, the other is a retry.
            $Status = if ($Message -match '401|Unauthorized|api-key') { 'not-configured' } else { 'error' }
            return @{
                Status         = $Status
                Reason         = if ($Status -eq 'not-configured') { 'service non configuré pour cette instance' } else { 'service indisponible' }
                CheckedUtc     = $CheckedUtc
                Source         = $Source
                Addresses      = $Queried
                AddressesTotal = @($Wanted).Count
                Breaches       = @()
                BreachCount    = 0
                PasswordCount  = 0
                YearMin        = $null
                YearMax        = $null
            }
        }

        # The rate-limit reply is a single OBJECT, not a list, so @() around it produces a
        # one-element array that reads exactly like one breach. Checked before anything else.
        #
        # Both shapes are tested for on purpose: Get-HIBPRequest builds a hashtable, and a
        # hashtable's PSObject.Properties are Keys/Values/Count, never the keys themselves - reading
        # only the properties let a rate limit through as a clean "no exposure".
        $RateLimited = if ($null -eq $Raw) {
            $false
        } elseif ($Raw -is [System.Collections.IDictionary]) {
            $Raw.Contains('rate-limit')
        } else {
            $Raw.PSObject.Properties.Name -contains 'rate-limit'
        }
        if ($RateLimited) {
            return @{
                Status         = 'rate-limited'
                Reason         = 'quota du service atteint'
                CheckedUtc     = $CheckedUtc
                Source         = $Source
                Addresses      = $Queried
                AddressesTotal = @($Wanted).Count
                Breaches       = @()
                BreachCount    = 0
                PasswordCount  = 0
                YearMin        = $null
                YearMax        = $null
                RetryAfter     = $Raw.Wait
            }
        }

        foreach ($Breach in @($Raw)) {
            if ($null -eq $Breach) { continue }
            $Name = [string]$Breach.Name
            if ([string]::IsNullOrWhiteSpace($Name)) { $Name = [string]$Breach.Title }
            if ([string]::IsNullOrWhiteSpace($Name)) { continue }
            if ($ByName.Contains($Name)) { continue }

            $Classes = @($Breach.DataClasses | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { [string]$_ })

            # WHITELIST. Everything not named here is dropped before persistence, Description and
            # any future field included. `Password` is a boolean derived from the classes, never a
            # value copied from the response.
            $ByName[$Name] = [ordered]@{
                Name        = [string]($Breach.Title ?? $Name)
                BreachDate  = if ([string]::IsNullOrWhiteSpace([string]$Breach.BreachDate)) { $null } else { [string]$Breach.BreachDate }
                DataClasses = $Classes
                Password    = [bool]($Classes | Where-Object { $_ -match '(?i)password' })
                LogoUrl     = [string]$Breach.LogoPath
            }
        }
    }

    $Breaches = @($ByName.Values)

    # Logos last, and on the deduplicated set only: fetching one per lookup would pull the same
    # image twice for an alias sharing a breach with the UPN.
    $LogoBudget = $MaxLogoTotalBytes
    foreach ($Breach in $Breaches) {
        $Url = $Breach.LogoUrl
        $Breach.Remove('LogoUrl')
        if ([string]::IsNullOrWhiteSpace($Url) -or $LogoBudget -le 0) { continue }
        try {
            $Logo = & $FetchLogo $Url
            $Bytes = $Logo.Bytes
            if ($null -eq $Bytes -or $Bytes.Length -eq 0 -or $Bytes.Length -gt $MaxLogoBytes) { continue }
            if ($Bytes.Length -gt $LogoBudget) { continue }
            # A truncated image is worse than a missing one: @react-pdf/renderer does not raise on a
            # malformed PNG, it HANGS - the render sits on an unresolved promise until something
            # times out, in the browser as well as in Node. So the bytes are checked for a complete
            # PNG here, where a rejected logo costs nothing, rather than trusted at render time.
            if (-not (Test-PsitPngComplete -Bytes $Bytes)) { continue }
            $Type = if ([string]::IsNullOrWhiteSpace($Logo.ContentType)) { 'image/png' } else { $Logo.ContentType }
            $Breach.Logo = "data:$Type;base64,$([Convert]::ToBase64String($Bytes))"
            $LogoBudget -= $Bytes.Length
        } catch {
            # Silent on purpose. A missing logo is not a finding.
            continue
        }
    }

    $Years = @(
        $Breaches |
            ForEach-Object { if ($_.BreachDate) { [int]([string]$_.BreachDate).Substring(0, 4) } } |
            Where-Object { $_ -gt 0 }
    )

    return @{
        Status         = 'ok'
        Reason         = $null
        CheckedUtc     = $CheckedUtc
        Source         = $Source
        Addresses      = $Queried
        AddressesTotal = @($Wanted).Count
        AddressesSkipped = $Skipped
        Breaches       = $Breaches
        BreachCount    = @($Breaches).Count
        PasswordCount  = @($Breaches | Where-Object { $_.Password }).Count
        YearMin        = if (@($Years).Count -gt 0) { ($Years | Measure-Object -Minimum).Minimum } else { $null }
        YearMax        = if (@($Years).Count -gt 0) { ($Years | Measure-Object -Maximum).Maximum } else { $null }
    }
}
