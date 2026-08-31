function Start-PSITCaseAuditSearch {
    <#
    .SYNOPSIS
        Asks the unified audit log the question a dossier's type raises, and files the search.

    .DESCRIPTION
        The download search (type 20) taught the pattern: the guide steps that say 'retrouver la
        création dans l'audit' used to mean a console and a notepad. This generalises it to the
        types whose answer lives in the unified audit log:

        - type 4 (privilege elevation): directory role membership changes;
        - type 5 (inbox rule or forward): inbox rule and mailbox forwarding operations;
        - type 7 (account or mailbox access): mailbox permissions, delegations, account creation.

        Same custody contract as the download search: created once per dossier, filed on it
        (Evidence.audit), a widened window keeps the search it replaces, and the summary is
        captured at the first finished read because the search expires with the journal.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,

        [Parameter(Mandatory = $true)]
        [int]$TypeId,

        [Parameter(Mandatory = $true)]
        [string]$UserPrincipalName,

        [Parameter(Mandatory = $true)]
        [string]$CaseId,

        [Parameter(Mandatory = $true)]
        [string]$Analyst,

        # The alert's detection time: the window anchors on it, never on now.
        [string]$AroundUtc,

        [int]$HoursBefore = 48,
        [int]$HoursAfter = 4,

        # What the dossier already had filed, when relaunching over a wider window.
        $Previous
    )

    $Kind = Get-PSITAuditSearchKind -TypeId $TypeId
    if (-not $Kind) {
        throw "Type $TypeId has no audit search defined."
    }

    $Anchor = $null
    if (-not [string]::IsNullOrWhiteSpace($AroundUtc)) {
        try { $Anchor = [datetime]::Parse($AroundUtc).ToUniversalTime() } catch { $Anchor = $null }
    }
    if (-not $Anchor) { $Anchor = (Get-Date).ToUniversalTime() }

    $Start = $Anchor.AddHours(-1 * [Math]::Abs($HoursBefore))
    $End = $Anchor.AddHours([Math]::Abs($HoursAfter))

    $Search = New-CippAuditLogSearch -TenantFilter $TenantFilter `
        -DisplayName "PSIT $CaseId - $($Kind.Label) - $UserPrincipalName" `
        -StartTime $Start -EndTime $End `
        -UserPrincipalNameFilters @($UserPrincipalName) `
        -OperationsFilters @($Kind.Operations) `
        -RecordTypeFilters @($Kind.RecordTypes)

    if (-not $Search.id) {
        throw "The audit search was not created: $([string]$Search.status) $([string]$Search.message)".Trim()
    }

    $LaunchedUtc = (Get-Date).ToUniversalTime().ToString('o')

    $History = [System.Collections.Generic.List[object]]::new()
    foreach ($Earlier in @($Previous.previous) + @($Previous)) {
        if (-not $Earlier -or [string]::IsNullOrWhiteSpace([string]$Earlier.searchId)) { continue }
        $History.Add([pscustomobject]@{
                searchId    = [string]$Earlier.searchId
                startUtc    = [string]$Earlier.startUtc
                endUtc      = [string]$Earlier.endUtc
                launchedUtc = [string]$Earlier.launchedUtc
                launchedBy  = [string]$Earlier.launchedBy
            })
    }

    $null = Set-PSITSocCase -TenantFilter $TenantFilter -CaseId $CaseId -Analyst $Analyst -Evidence @{
        audit = [pscustomobject]@{
            kind        = [string]$Kind.Key
            searchId    = [string]$Search.id
            user        = $UserPrincipalName
            startUtc    = $Start.ToString('o')
            endUtc      = $End.ToString('o')
            launchedUtc = $LaunchedUtc
            launchedBy  = $Analyst
            previous    = @($History)
        }
    }

    Write-LogMessage -API 'PSITCaseAuditSearch' -tenant $TenantFilter -message "Audit search $($Search.id) ($($Kind.Key)) started for $UserPrincipalName on case $CaseId by $Analyst" -sev Info

    [pscustomobject]@{
        SearchId    = [string]$Search.id
        Kind        = [string]$Kind.Key
        StartUtc    = $Start.ToString('o')
        EndUtc      = $End.ToString('o')
        LaunchedUtc = $LaunchedUtc
        Status      = [string]$Search.status
    }
}
