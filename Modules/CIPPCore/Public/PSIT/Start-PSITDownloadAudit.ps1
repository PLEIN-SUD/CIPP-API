function Start-PSITDownloadAudit {
    <#
    .SYNOPSIS
        Asks the unified audit log which files an account actually pulled, and when.

    .DESCRIPTION
        A mass-download alert says a number and a name. The investigation needs the list: which
        files, from which sites, over how long, and from where. That list exists in the unified
        audit log and nowhere else the portal can reach, so the panel that used to show the alert
        back to the analyst now asks the question the alert raises.

        The search is created once per dossier and its id is filed on it. Audit searches are
        asynchronous - minutes, sometimes more - so a second visit must find the search that is
        already running rather than start another one, and a report written later must be able to
        name the search its numbers came from.

        The window is the alert's own hour, widened either side, because the emitter reports the
        moment it ingested the behaviour and the download itself started earlier.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TenantFilter,

        [Parameter(Mandatory)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory)]
        [string]$CaseId,

        [Parameter(Mandatory)]
        [string]$Analyst,

        # The alert's detection time. The window is built around it rather than around now: a
        # dossier opened the next morning would otherwise search a day when nothing happened.
        [string]$AroundUtc,

        [int]$HoursBefore = 12,
        [int]$HoursAfter = 4,

        # What the dossier already had filed, when the analyst relaunches over a wider window.
        # Kept beside the new search rather than overwritten: a report written this morning quotes
        # numbers that came from a particular search, and "which search said that" must stay
        # answerable after the window is widened.
        $Previous
    )

    $Anchor = $null
    if (-not [string]::IsNullOrWhiteSpace($AroundUtc)) {
        try { $Anchor = [datetime]::Parse($AroundUtc).ToUniversalTime() } catch { $Anchor = $null }
    }
    if (-not $Anchor) { $Anchor = (Get-Date).ToUniversalTime() }

    $Start = $Anchor.AddHours(-1 * [Math]::Abs($HoursBefore))
    $End = $Anchor.AddHours([Math]::Abs($HoursAfter))

    $Search = New-CippAuditLogSearch -TenantFilter $TenantFilter `
        -DisplayName "PSIT $CaseId - téléchargements de $UserPrincipalName" `
        -StartTime $Start -EndTime $End `
        -UserPrincipalNameFilters @($UserPrincipalName) `
        -OperationsFilters @('FileDownloaded', 'FileSyncDownloadedFull', 'FileAccessed') `
        -RecordTypeFilters @('sharePointFileOperation', 'oneDrive')

    if (-not $Search.id) {
        # Unified auditing off, or the tenant refused: the caller says so rather than showing an
        # empty file list, which would read as an account that downloaded nothing.
        throw "The audit search was not created: $([string]$Search.status) $([string]$Search.message)".Trim()
    }

    $LaunchedUtc = (Get-Date).ToUniversalTime().ToString('o')

    # Every search this dossier ever ran, oldest first, minus its records: only the identity of
    # the search and the window it covered, which is what a report needs to name its source.
    $History = [System.Collections.Generic.List[object]]::new()
    foreach ($Earlier in @($Previous.previous) + @($Previous)) {
        if (-not $Earlier -or [string]::IsNullOrWhiteSpace([string]$Earlier.searchId)) { continue }
        $History.Add([pscustomobject]@{
                searchId    = [string]$Earlier.searchId
                user        = [string]$Earlier.user
                startUtc    = [string]$Earlier.startUtc
                endUtc      = [string]$Earlier.endUtc
                launchedUtc = [string]$Earlier.launchedUtc
                launchedBy  = [string]$Earlier.launchedBy
            })
    }

    # Filed on the dossier, which is what makes a second visit find this search instead of
    # starting another, and what lets a report name where its numbers came from.
    $null = Set-PSITSocCase -TenantFilter $TenantFilter -CaseId $CaseId -Analyst $Analyst -Evidence @{
        download = [pscustomobject]@{
            searchId    = [string]$Search.id
            displayName = [string]$Search.displayName
            user        = $UserPrincipalName
            startUtc    = $Start.ToString('o')
            endUtc      = $End.ToString('o')
            launchedUtc = $LaunchedUtc
            launchedBy  = $Analyst
            previous    = @($History)
        }
    }

    Write-LogMessage -API 'PSITDownloadAudit' -tenant $TenantFilter -message "Audit search $($Search.id) started for $UserPrincipalName on case $CaseId by $Analyst" -sev Info

    [pscustomobject]@{
        SearchId    = [string]$Search.id
        DisplayName = [string]$Search.displayName
        StartUtc    = $Start.ToString('o')
        EndUtc      = $End.ToString('o')
        LaunchedUtc = $LaunchedUtc
        Status      = [string]$Search.status
    }
}
