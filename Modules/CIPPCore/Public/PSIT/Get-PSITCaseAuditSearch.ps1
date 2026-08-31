function Get-PSITCaseAuditSearch {
    <#
    .SYNOPSIS
        Reads back a dossier audit search: is it finished, and what did it record.

    .DESCRIPTION
        Same contract as the download reading: a running search is said to be running (never an
        empty list, which would read as 'nothing happened'), the records arrive mapped to what an
        analyst asks (when, which operation, who did it, on what, from where), and the summary is
        computed here because the reports quote it.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,

        [Parameter(Mandatory = $true)]
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

    $Rows = @()
    try {
        $Rows = @(Get-CippAuditLogSearchResults -TenantFilter $TenantFilter -QueryId $SearchId)
    } catch {
        $Warnings.Add("Résultats illisibles ($($_.Exception.Message)).")
    }

    $Events = [System.Collections.Generic.List[object]]::new()
    foreach ($Row in @($Rows | Where-Object { $_ })) {
        $Data = if ($null -ne $Row.auditData) { $Row.auditData } else { $Row }
        $Operation = [string]$Data.Operation
        if ([string]::IsNullOrWhiteSpace($Operation)) { continue }
        # Parameters is an array of Name/Value pairs, not an object: Identity has to be fished out.
        $Target = [string]$Data.ObjectId
        if ([string]::IsNullOrWhiteSpace($Target) -and $Data.Parameters) {
            $Target = [string](@($Data.Parameters) | Where-Object { $_.Name -eq 'Identity' } | Select-Object -First 1).Value
        }
        $Events.Add([pscustomobject]@{
                WhenUtc   = if ($Data.CreationTime) { [string]$Data.CreationTime } else { [string]$Row.createdDateTime }
                Operation = $Operation
                Actor     = [string]$Data.UserId
                Target    = $Target
                Ip        = [string]$Data.ClientIP
                # The raw parameters carry the substance (rule conditions, granted rights):
                # compact, capped, for the drawer and the report annex.
                Detail    = if ($Data.Parameters) {
                    ([string]($Data.Parameters | ConvertTo-Json -Depth 3 -Compress)).Substring(0, [Math]::Min(500, ([string]($Data.Parameters | ConvertTo-Json -Depth 3 -Compress)).Length))
                } else { '' }
            })
    }

    $Operations = @{}
    $Actors = @{}
    foreach ($Event in $Events) {
        if ($Event.Operation) { $Operations[$Event.Operation] = ([int]$Operations[$Event.Operation]) + 1 }
        if ($Event.Actor) { $Actors[$Event.Actor] = ([int]$Actors[$Event.Actor]) + 1 }
    }
    $Stamps = @($Events | ForEach-Object { $_.WhenUtc } | Where-Object { $_ } | Sort-Object)
    $Addresses = @($Events | ForEach-Object { $_.Ip } | Where-Object { $_ } | Sort-Object -Unique)

    [pscustomobject]@{
        SearchId = $SearchId
        Status   = if ($Status) { $Status } else { 'succeeded' }
        Running  = $false
        Records  = @($Events)
        Summary  = [pscustomobject]@{
            EventCount   = $Events.Count
            Operations   = @($Operations.GetEnumerator() | Sort-Object -Property Value -Descending | ForEach-Object {
                    [pscustomobject]@{ Operation = $_.Key; Count = $_.Value }
                })
            Actors       = @($Actors.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 8 | ForEach-Object {
                    [pscustomobject]@{ Actor = $_.Key; Count = $_.Value }
                })
            Addresses    = @($Addresses | Select-Object -First 10)
            AddressCount = $Addresses.Count
            FirstUtc     = if ($Stamps.Count -gt 0) { $Stamps[0] } else { '' }
            LastUtc      = if ($Stamps.Count -gt 0) { $Stamps[-1] } else { '' }
        }
        Warnings = @($Warnings)
    }
}
