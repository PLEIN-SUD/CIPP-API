function Get-PSITDownloadAudit {
    <#
    .SYNOPSIS
        Reads back a download audit search: is it finished, and what did it find.

    .DESCRIPTION
        Answers the three questions the panel asks in order: is the search still running, how many
        records came back, and what do they amount to - which sites, which file types, over which
        hours, from which addresses, through which client.

        The summary is computed here rather than in the browser because it is what the report
        quotes: a page of raw records is evidence nobody reads, and a client asking "what was
        taken" wants the shape of it. The user agent is part of that shape - a sync client pulling
        a library it was already syncing and a browser pulling it file by file are two different
        stories told by the same file count.

        A search that is still running is said to be running. It is the state a mass-download
        investigation spends most of its first minutes in, and a panel that showed an empty list
        instead would read as an account that downloaded nothing.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TenantFilter,

        [Parameter(Mandatory)]
        [string]$SearchId
    )

    $Warnings = [System.Collections.Generic.List[string]]::new()

    $Status = 'unknown'
    try {
        $Query = New-GraphGetRequest -uri "https://graph.microsoft.com/beta/security/auditLog/queries/$SearchId" -tenantid $TenantFilter -AsApp $true
        $Status = [string]$Query.status
    } catch {
        $Warnings.Add("État de la recherche illisible ($($_.Exception.Message)).")
    }

    if ($Status -and $Status -ne 'succeeded') {
        return [pscustomobject]@{
            SearchId = $SearchId
            Status   = $Status
            Running  = $true
            Records  = @()
            Summary  = $null
            Warnings = @($Warnings)
        }
    }

    $Records = @()
    try {
        $Records = @(Get-CippAuditLogSearchResults -TenantFilter $TenantFilter -QueryId $SearchId)
    } catch {
        $Warnings.Add("Résultats illisibles ($($_.Exception.Message)).")
    }

    $Files = [System.Collections.Generic.List[object]]::new()
    foreach ($Record in @($Records | Where-Object { $_ })) {
        # The search API nests the Office 365 schema under auditData; a record read from anywhere
        # else is already flat.
        $Data = if ($null -ne $Record.auditData) { $Record.auditData } else { $Record }
        $Path = [string]$Data.ObjectId
        if ([string]::IsNullOrWhiteSpace($Path)) { continue }
        # SourceFileName when the schema carries it, the tail of the URL otherwise: a file named
        # by its full site path is unreadable in a table and useless in a report.
        $Name = [string]$Data.SourceFileName
        if ([string]::IsNullOrWhiteSpace($Name)) { $Name = ($Path -split '/')[-1] }
        $Files.Add([pscustomobject]@{
                Path      = $Path
                Name      = $Name
                Site      = [string]$Data.SiteUrl
                Operation = [string]$Data.Operation
                WhenUtc   = if ($Data.CreationTime) { [string]$Data.CreationTime } else { [string]$Record.createdDateTime }
                Ip        = [string]$Data.ClientIP
                Agent     = [string]$Data.UserAgent
            })
    }

    $Extensions = @{}
    $Operations = @{}
    foreach ($File in $Files) {
        if (-not [string]::IsNullOrWhiteSpace($File.Operation)) {
            $Operations[$File.Operation] = ([int]$Operations[$File.Operation]) + 1
        }
        $Extension = if ($File.Name -match '\.([A-Za-z0-9]{1,8})$') { $Matches[1].ToLowerInvariant() } else { 'sans extension' }
        $Extensions[$Extension] = ([int]$Extensions[$Extension]) + 1
    }

    $Stamps = @($Files | ForEach-Object { $_.WhenUtc } | Where-Object { $_ } | Sort-Object)
    $Addresses = @($Files | ForEach-Object { $_.Ip } | Where-Object { $_ } | Sort-Object -Unique)
    $Sites = @($Files | ForEach-Object { $_.Site } | Where-Object { $_ } | Sort-Object -Unique)
    $Agents = @($Files | ForEach-Object { $_.Agent } | Where-Object { $_ } | Sort-Object -Unique)

    [pscustomobject]@{
        SearchId = $SearchId
        Status   = if ($Status) { $Status } else { 'succeeded' }
        Running  = $false
        Records  = @($Files)
        Summary  = [pscustomobject]@{
            FileCount    = $Files.Count
            SiteCount    = $Sites.Count
            Sites        = @($Sites | Select-Object -First 10)
            Extensions   = @($Extensions.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 8 | ForEach-Object {
                    [pscustomobject]@{ Extension = $_.Key; Count = $_.Value }
                })
            FirstUtc     = if ($Stamps.Count -gt 0) { $Stamps[0] } else { '' }
            LastUtc      = if ($Stamps.Count -gt 0) { $Stamps[-1] } else { '' }
            Addresses    = @($Addresses | Select-Object -First 10)
            AddressCount = $Addresses.Count
            Agents       = @($Agents | Select-Object -First 5)
            # Read one thing, downloaded another: the report leans on this split, because a page
            # of FileAccessed records is not a data exfiltration.
            Operations   = @($Operations.GetEnumerator() | Sort-Object -Property Value -Descending | ForEach-Object {
                    [pscustomobject]@{ Operation = $_.Key; Count = $_.Value }
                })
        }
        Warnings = @($Warnings)
    }
}
