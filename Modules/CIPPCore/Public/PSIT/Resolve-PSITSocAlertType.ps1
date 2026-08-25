function Resolve-PSITSocAlertType {
    <#
    .SYNOPSIS
        Turns the subject line of an external SOC notification into an alert type.

    .DESCRIPTION
        The notification arrives as an email whose subject carries everything the queue needs:
        "[SOC x <scope>] - <label> - <target>", sometimes behind reply prefixes added by whoever
        forwarded it. Parsing it here means the caller posts the raw subject and never has to
        reproduce this, and that the rules live in one place with tests around them.

        Patterns are tried in the order the configuration declares. That order is load bearing:
        the binary activity pattern matches almost any subject starting with a French word for
        activity, so it comes last, after the identity labels it would otherwise swallow.

        A subject matching nothing resolves to the catch-all type rather than to nothing. An
        emitter adds rules without telling anyone, and a type nobody recognises is a taxonomy to
        extend, never an alert to drop: the case opens, the analyst sets the type, and the
        unmatched subject is reported so the table can be completed.

        The label the SOC uses is not the detection product. It transports Defender, Defender for
        Office and Entra detections alike, so the answer carries DetectionSource separately: the
        same type reaching us by two channels must not be counted twice, and must not be filed
        under the channel it happened to arrive through.

    .PARAMETER Subject
        The raw subject line, reply prefixes included.

    .PARAMETER Catalogue
        Injected configuration. Read from Config/PSITSocAlertTypes.json when omitted.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Subject,

        [AllowNull()]
        $Catalogue
    )

    if ($null -eq $Catalogue) {
        $Path = Join-Path $env:CIPPRootPath 'Config\PSITSocAlertTypes.json'
        $Catalogue = Get-Content -Path $Path -Raw -Encoding utf8 | ConvertFrom-Json
    }

    $CatchAll = [int]$Catalogue.catchAllTypeId
    $Unmatched = [pscustomobject]@{
        TypeId          = $CatchAll
        LabelId         = 'CATCHALL'
        DetectionSource = 'unknown'
        Status          = 'UNMATCHED'
        Scope           = ''
        Target          = ''
        Label           = [string]$Subject
        Matched         = $false
        OutOfScope      = $false
    }

    if ([string]::IsNullOrWhiteSpace($Subject)) { return $Unmatched }

    # Reply prefixes stack: a forwarded forward carries several. The pattern repeats, so one pass
    # clears them all.
    $Clean = [regex]::Replace($Subject, $Catalogue.subject.StripPrefixPattern, '', 'IgnoreCase').Trim()

    $Scope = ''
    $Target = ''
    $Label = $Clean
    $Master = [regex]::Match($Clean, $Catalogue.subject.MasterPattern, 'IgnoreCase')
    if ($Master.Success) {
        $Scope = $Master.Groups['scope'].Value.Trim()
        $Label = $Master.Groups['label'].Value.Trim()
        $Target = $Master.Groups['target'].Value.Trim()
    }
    if ([string]::IsNullOrWhiteSpace($Target)) {
        # No " - " separator: the target is buried in the label, as in a subject naming the actor
        # inline. Recovered from the label rather than left empty.
        $Fallback = [regex]::Match($Label, $Catalogue.subject.TargetFallbackPattern, 'IgnoreCase')
        if ($Fallback.Success) { $Target = $Fallback.Groups['target'].Value.Trim() }
    }

    # Out of scope before in scope: an alert this portal cannot investigate has to be recognised
    # as such, not filed under the catch-all where it would look like a taxonomy gap.
    foreach ($Entry in @($Catalogue.outOfScope)) {
        if ([regex]::IsMatch($Label, $Entry.Pattern, 'IgnoreCase')) {
            return [pscustomobject]@{
                TypeId          = $CatchAll
                LabelId         = [string]$Entry.LabelId
                DetectionSource = 'unknown'
                Status          = 'OUT_OF_SCOPE'
                Scope           = $Scope
                Target          = $Target
                Label           = $Label
                Matched         = $true
                OutOfScope      = $true
                Reason          = [string]$Entry.Reason
            }
        }
    }

    foreach ($Entry in @($Catalogue.patterns)) {
        if ([regex]::IsMatch($Label, $Entry.Pattern, 'IgnoreCase')) {
            return [pscustomobject]@{
                TypeId          = [int]$Entry.TypeId
                LabelId         = [string]$Entry.LabelId
                DetectionSource = [string]$Entry.DetectionSource
                Status          = [string]$Entry.Status
                Scope           = $Scope
                Target          = $Target
                Label           = $Label
                Matched         = $true
                OutOfScope      = $false
            }
        }
    }

    $Unmatched.Scope = $Scope
    $Unmatched.Target = $Target
    $Unmatched.Label = $Label
    return $Unmatched
}
