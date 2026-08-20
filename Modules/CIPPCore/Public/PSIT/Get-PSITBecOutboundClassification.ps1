function Get-PSITBecOutboundClassification {
    <#
    .SYNOPSIS
        Classifies outbound message trace rows before any pattern analysis runs on them.

    .DESCRIPTION
        The mass-mail heuristics only mean something on mail a human actually sent to someone
        outside the organisation. Applied to the raw trace they fire on ordinary work, which is
        how a recruiter's morning ("RE: CV Alexandre", "Fwd: consultation") became a "mass-mail
        pattern" in a real report while the one genuine signal sat further down the page.

        Each row is tagged:
          - SystemGenerated: an automatic reply, out-of-office or non-delivery report. The subject
            prefixes are matched in the languages this tenant estate actually uses, plus the
            English ones Exchange emits regardless of mailbox language.
          - ServiceIp: submitted by Microsoft's own infrastructure (see Test-PSITBecServiceIp), so
            its geolocation says nothing about where the user was.
          - Internal: recipient in the sender's own domain. Internal mail is not exfiltration and
            not fraud toward a third party.

        Campaign and burst detection then runs on the human, external subset only, while the
        counters keep the full picture so nothing is hidden - a reader sees 177 messages sent,
        of which 166 service-generated, rather than either number alone.

    .PARAMETER TraceRows
        Rows from Get-MessageTraceV2 (one row per recipient).

    .PARAMETER SenderAddress
        The investigated mailbox. Its domain defines "internal".

    .PARAMETER GeoMap
        Optional hashtable of address -> geo record, as built by the caller.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [AllowEmptyCollection()]
        $TraceRows,

        [Parameter(Mandatory = $true)]
        [string]$SenderAddress,

        [hashtable]$GeoMap = @{}
    )

    # Subject prefixes Exchange and Outlook use for mail the service or the client generates on
    # the user's behalf. French and English cover this estate; German and Spanish are cheap to
    # keep for tenants with mixed-language mailboxes.
    $SystemSubjectPattern = '^\s*(r[ée]ponse\s+auto(matique)?|automatic\s+reply|automatische\s+antwort|respuesta\s+autom[áa]tica|out\s+of\s+office|undeliverable|non[- ]remis|[ée]chec\s+de\s+la\s+remise|delivery\s+status\s+notification|mail\s+delivery\s+failed)\s*[:\-]'

    $SenderDomain = ($SenderAddress -split '@')[-1]
    $Rows = @($TraceRows | Where-Object { $_ })

    $Classified = foreach ($Row in $Rows) {
        $Subject = [string]$Row.Subject
        $RecipientDomain = ([string]$Row.RecipientAddress -split '@')[-1]
        $Geo = if ($Row.FromIP -and $GeoMap.ContainsKey([string]$Row.FromIP)) { $GeoMap[[string]$Row.FromIP] } else { $null }

        $Row | Select-Object *, `
        @{ Name = 'SystemGenerated'; Expression = { [bool]($Subject -match $SystemSubjectPattern) } }, `
        @{ Name = 'ServiceIp'; Expression = { [bool](Test-PSITBecServiceIp -Ip $Row.FromIP -GeoInfo $Geo) } }, `
        @{ Name = 'Internal'; Expression = { [bool]($RecipientDomain -and $RecipientDomain -eq $SenderDomain) } }
    }

    $Classified = @($Classified)
    # The subset the heuristics may look at: sent by the person, to someone outside.
    $Analysable = @($Classified | Where-Object { -not $_.SystemGenerated -and -not $_.Internal })

    $RepeatSubjectMessages = 5
    $RepeatSubjectRecipients = 20
    $BurstMessages = 10
    $BurstRecipients = 30
    $BurstWindowTicks = [timespan]::FromMinutes(10).Ticks

    $RepeatedSubjects = @($Analysable | Group-Object -Property { ([string]$_.Subject).Trim().ToLowerInvariant() } | ForEach-Object {
            $MessageCount = @($_.Group.MessageTraceId | Select-Object -Unique).Count
            $Times = @($_.Group.Received | Where-Object { $_ } | Sort-Object)
            [pscustomobject]@{
                Subject        = if ([string]::IsNullOrWhiteSpace($_.Group[0].Subject)) { '(no subject)' } else { [string]$_.Group[0].Subject }
                MessageCount   = $MessageCount
                RecipientCount = $_.Count
                FirstSent      = if ($Times.Count -gt 0) { ([datetime]$Times[0]).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
                LastSent       = if ($Times.Count -gt 0) { ([datetime]$Times[-1]).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null }
                Flagged        = ($MessageCount -ge $RepeatSubjectMessages -or $_.Count -ge $RepeatSubjectRecipients)
            }
        } | Where-Object { $_.MessageCount -ge 3 -or $_.Flagged } | Sort-Object -Property MessageCount -Descending | Select-Object -First 10)

    $Bursts = @($Analysable | Where-Object { $_.Received } | Group-Object -Property { [long](([datetime]$_.Received).ToUniversalTime().Ticks / $BurstWindowTicks) } | ForEach-Object {
            $MessageCount = @($_.Group.MessageTraceId | Select-Object -Unique).Count
            if ($MessageCount -ge $BurstMessages -or $_.Count -ge $BurstRecipients) {
                $TopSubject = ($_.Group | Group-Object -Property Subject | Sort-Object -Property Count -Descending | Select-Object -First 1).Name
                [pscustomobject]@{
                    WindowStart    = [datetime]::new(([long]$_.Name) * $BurstWindowTicks, [System.DateTimeKind]::Utc).ToString('yyyy-MM-ddTHH:mm:ssZ')
                    WindowMinutes  = 10
                    MessageCount   = $MessageCount
                    RecipientCount = $_.Count
                    TopSubject     = if ([string]::IsNullOrWhiteSpace($TopSubject)) { '(no subject)' } else { $TopSubject }
                }
            }
        } | Sort-Object -Property RecipientCount -Descending | Select-Object -First 10)

    return [pscustomobject]@{
        Rows                    = $Classified
        AnalysableRows          = $Analysable
        TotalMessages           = @($Classified.MessageTraceId | Select-Object -Unique).Count
        TotalRecipients         = $Classified.Count
        SystemGeneratedMessages = @($Classified | Where-Object { $_.SystemGenerated } | Select-Object -ExpandProperty MessageTraceId -Unique).Count
        ServiceIpRecipients     = @($Classified | Where-Object { $_.ServiceIp }).Count
        InternalRecipients      = @($Classified | Where-Object { $_.Internal }).Count
        ExternalRecipients      = @($Classified | Where-Object { -not $_.Internal }).Count
        AnalysableMessages      = @($Analysable.MessageTraceId | Select-Object -Unique).Count
        RepeatedSubjects        = $RepeatedSubjects
        FlaggedSubjectCount     = @($RepeatedSubjects | Where-Object { $_.Flagged }).Count
        Bursts                  = $Bursts
        Flagged                 = (@($RepeatedSubjects | Where-Object { $_.Flagged }).Count -gt 0 -or @($Bursts).Count -gt 0)
    }
}
