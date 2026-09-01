function Find-PSITSocDuplicateCase {
    <#
    .SYNOPSIS
        Finds the dossier an arriving signal duplicates, across transports.

    .DESCRIPTION
        The same incident reaches the portal several ways: the external SOC's notification, the
        Defender XDR alert, the Defender for Office 365 alert - each with its own reference, so
        the ExternalRef idempotence never sees them as one. Two dossiers for one incident mean
        two half investigations and, worse, two half journals.

        A duplicate is an OPEN dossier of the same type, on the same tenant, naming the same
        primary entity (account, machine, application or message), created inside the window.
        Closed dossiers never match: a journal line on a closed dossier is an alert nobody sees,
        so a signal arriving after the closure opens a new dossier - and the enrichment's
        related-cases scan is what shows the analyst the closed sibling.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,

        [Parameter(Mandatory = $true)]
        [int]$TypeId,

        # The arriving signal's entities: only the identifying keys participate in the match.
        [Parameter(Mandatory = $true)]
        $Entities,

        [int]$WithinHours = 48
    )

    $Keys = @('upn', 'userId', 'deviceName', 'deviceId', 'appId', 'networkMessageId')
    $Values = @{}
    $EntityObject = [pscustomobject]$Entities
    foreach ($Key in $Keys) {
        $Value = [string]$EntityObject.$Key
        if (-not [string]::IsNullOrWhiteSpace($Value)) { $Values[$Key] = $Value }
    }
    # A signal naming nobody can duplicate nothing: matching on emptiness would glue together
    # every unattributed alert of the type.
    if ($Values.Count -eq 0) { return $null }

    $Cutoff = [datetime]::UtcNow.AddHours(-1 * [Math]::Abs($WithinHours))

    $Candidates = @(Get-PSITSocCase -TenantFilter $TenantFilter) | Where-Object {
        if ($_.Status -eq 'closed') { return $false }
        if ([string]$_.TypeId -ne [string]$TypeId) { return $false }
        $Created = $null
        try {
            $Created = [datetime]::Parse([string]$_.CreatedUtc, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal)
        } catch {
            return $false
        }
        if ($Created -lt $Cutoff) { return $false }
        foreach ($Key in $Values.Keys) {
            if ([string]$_.Entities.$Key -eq [string]$Values[$Key]) { return $true }
        }
        return $false
    }

    @($Candidates | Sort-Object -Property CreatedUtc -Descending) | Select-Object -First 1
}
